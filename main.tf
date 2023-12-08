terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.30.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "vpc" {
  source         = "terraform-aws-modules/vpc/aws"
  name           = "data-team-vpc"
  cidr           = "10.0.0.0/16"
  azs            = ["us-east-1a", "us-east-1b"]
  public_subnets = ["10.0.21.0/24", "10.0.22.0/24"]

  public_dedicated_network_acl = true
  enable_dns_hostnames         = true
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

provider "aws" {
  alias  = "security_provider"
  region = var.security_aws_region

  default_tags {
    tags = {
      stage       = var.stage
      Environment = "${var.service_name}-service-${var.stage}"
    }
  }
}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  aws_partition = data.aws_partition.current.id

  repo_root     = "${path.root}/.."
  data_api_root = "${local.repo_root}/services/data_api"

  subservice_name = "data-api"
  resource_prefix = "${var.service_abbreviation}-${local.subservice_name}"

  // If any of these files change, we need to redeploy.
  source_files = setunion(
    fileset(local.data_api_root, "app/**/*.py"),
    [
      "Dockerfile",
      "Pipfile",
      "Pipfile.lock",
      "log_config.yaml",
    ]
  )
  source_hash = sha256(
    join(":", [for file_path in sort(local.source_files) : filesha256("${local.data_api_root}/${file_path}")])
  )

  app_port = 8000
}

resource "aws_security_group" "data_api_lb_security_group" {
  name        = "${local.resource_prefix}-alb-sg-${var.stage}"
  description = "The security group of the Data API application load balancer."
  vpc_id      = var.network_config.vpc_id

  egress { // Allow outbound traffic to `app_port`. Required for health checks.
    from_port   = local.app_port
    to_port     = local.app_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress { // Allow only inbound HTTPS traffic.
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "data_api_task_security_group" {
  name        = "${local.resource_prefix}-task-sg-${var.stage}"
  description = "The security group of the Data API tasks."
  vpc_id      = var.network_config.vpc_id

  egress { // No restrictions for outbound traffic.
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress { // Allow only inbound traffic to the `app_port` from the load balancer.
    from_port       = local.app_port
    to_port         = local.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.data_api_lb_security_group.id]
  }
}

resource "aws_lb" "data_api_load_balancer" {
  name               = "${local.resource_prefix}-load-balancer-${var.stage}"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.network_config.public_subnet_ids
  security_groups    = [aws_security_group.data_api_lb_security_group.id]
  idle_timeout       = 20

  access_logs {
    bucket  = var.load_balancer_logs_bucket
    prefix  = "data_api_lb_logs"
    enabled = true
  }
}

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.data_api_load_balancer.arn
  protocol          = "HTTPS"
  port              = 443
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.data_api_target_group.arn
  }
}

resource "aws_lb_target_group" "data_api_target_group" {
  name        = "${local.resource_prefix}-target-group-${var.stage}"
  target_type = "ip" # For targetting fargate instances, the "ip" target_type is required.
  protocol    = "HTTP"
  port        = local.app_port
  vpc_id      = var.network_config.vpc_id

  health_check {
    protocol            = "HTTP"
    port                = local.app_port
    path                = "/healthcheck"
    matcher             = "200"
    interval            = 10
    timeout             = 3
    healthy_threshold   = 3
    unhealthy_threshold = 2
  }
}

resource "aws_ecr_repository" "data_api_repo" {
  name                 = "${local.resource_prefix}-repo-${var.stage}"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "null_resource" "build_and_push_image" {
  triggers = {
    src_hash        = local.source_hash
    otel_cert_hash  = sha256(var.otel_collector_config.cert)
    rate_limit_hash = sha256(jsonencode(var.rate_limit_config))
    app_version     = var.app_version
  }

  provisioner "local-exec" {
    working_dir = local.data_api_root
    interpreter = ["/bin/bash", "-ce"]
    environment = {
      ECR_REPO_URL                     = aws_ecr_repository.data_api_repo.repository_url
      CODEARTIFACT_REPOSITORY_AUTH_URL = var.codeartifact_repository_auth_url
      OTEL_TLS_CERT                    = var.otel_collector_config.cert
    }

    command = <<-EOT
      aws ecr get-login-password --region ${var.region} \
        | docker login --username AWS --password-stdin ${local.account_id}.dkr.ecr.${var.region}.amazonaws.com

      echo '${jsonencode(var.rate_limit_config)}' > rate_limit_config.json

      # Build "python-deps" stage with inline cache metadata. Tag as "python-deps"
      docker build . \
        --target python-deps \
        --platform linux/amd64 \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        --cache-from $${ECR_REPO_URL}:python-deps \
        --secret id=repo_url,env=CODEARTIFACT_REPOSITORY_AUTH_URL \
        --tag $${ECR_REPO_URL}:python-deps

      # Build "runtime" stage with line cache metadata. Tag as "runtime"
      docker build . \
        --target runtime \
        --platform linux/amd64 \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        --build-arg OTEL_TLS_CERT="$${OTEL_TLS_CERT}" \
        --cache-from $${ECR_REPO_URL}:python-deps \
        --cache-from $${ECR_REPO_URL}:runtime \
        --tag $${ECR_REPO_URL}:runtime \
        --tag $${ECR_REPO_URL}:${var.app_version}

      # Push all tags to the registry
      docker push $${ECR_REPO_URL}:python-deps
      docker push $${ECR_REPO_URL}:runtime
      docker push $${ECR_REPO_URL}:${var.app_version}
    EOT
  }
}

data "aws_ecr_image" "data_api_image" {
  depends_on = [
    null_resource.build_and_push_image
  ]

  repository_name = aws_ecr_repository.data_api_repo.name
  image_tag       = var.app_version
}

resource "aws_ecs_cluster" "data_api_cluster" {
  name = "${local.resource_prefix}-cluster-${var.stage}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

data "aws_iam_policy_document" "ecs_tasks_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "data_api_task_policy" {
  statement {
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "ssm:GetParametersByPath",
      "ssm:GetParameters",
      "ssm:GetParameter",
    ]
    resources = [
      "arn:aws:ssm:${var.region}:${local.account_id}:parameter/${var.stage}/data-api/*"
    ]
    effect = "Allow"
  }
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:BatchGetItem",
      "dynamodb:Query",
    ]
    resources = [
      var.timeline_table.arn,
      var.timeline_table.arm_index_arn
    ]
    effect = "Allow"
  }
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:Query",
    ]
    resources = [
      var.subscriptions_table.arn,
      "${var.subscriptions_table.arn}/index/${var.subscriptions_table.user_index_name}",
      "${var.subscriptions_table.arn}/index/${var.subscriptions_table.endpoint_index_name}",
    ]
    effect = "Allow"
  }
  statement {
    actions = [
      "sns:DeleteEndpoint",
      "sns:CreatePlatformEndpoint",
    ]
    resources = [
      var.platform_app_arn
    ]
    effect = "Allow"
  }
  statement {
    effect = "Allow"
    actions = [
      "sqs:SendMessage"
    ]
    resources = [
      var.event_filter_queue.arn,
      var.event_timeline_queue.arn
    ]
  }
}

resource "aws_iam_role" "data_api_execution_role" {
  name               = "${local.resource_prefix}-execution-role-${var.stage}"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust_policy.json
}

resource "aws_iam_role_policy_attachment" "ecs_execution_role_policy_attachment" {
  role       = aws_iam_role.data_api_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "data_api_task_role" {
  name               = "${local.resource_prefix}-task-role-${var.stage}"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust_policy.json

  inline_policy {
    name   = "${local.resource_prefix}-task-role-policy"
    policy = data.aws_iam_policy_document.data_api_task_policy.json
  }
}

resource "aws_cloudwatch_log_group" "data_api_log_group" {
  name              = "/fargate/service/${local.resource_prefix}-task-${var.stage}"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_subscription_filter" "datadog_forwarder_log_filter" {
  name            = "DataDogForwarder-${local.resource_prefix}-task-${var.stage}"
  log_group_name  = aws_cloudwatch_log_group.data_api_log_group.name
  filter_pattern  = ""
  destination_arn = var.datadog_forwarder_lambda_arn
}

resource "aws_ecs_task_definition" "data_api_task_definition" {
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  family                   = "${local.resource_prefix}-task-definition-${var.stage}"
  cpu                      = var.task_config.cpu
  memory                   = var.task_config.memory
  execution_role_arn       = aws_iam_role.data_api_execution_role.arn
  task_role_arn            = aws_iam_role.data_api_task_role.arn

  container_definitions = jsonencode([{
    name      = "data_api"
    image     = "${aws_ecr_repository.data_api_repo.repository_url}@${data.aws_ecr_image.data_api_image.id}"
    essential = true
    cpu       = var.task_config.cpu
    memory    = var.task_config.memory
    environment = [
      for key, val in {
        STAGE                                   = var.stage
        APP_VERSION                             = var.app_version
        AWS_REGION                              = var.region
        AWS_DEFAULT_REGION                      = var.region
        TIMELINE_TABLE_NAME                     = var.timeline_table.name
        TIMELINE_TABLE_ARM_INDEX_NAME           = var.timeline_table.arm_index_name
        SUBSCRIPTIONS_TABLE_NAME                = var.subscriptions_table.name
        SUBSCRIPTIONS_TABLE_USER_INDEX_NAME     = var.subscriptions_table.user_index_name
        SUBSCRIPTIONS_TABLE_ENDPOINT_INDEX_NAME = var.subscriptions_table.endpoint_index_name
        PLATFORM_APP_ARN                        = var.platform_app_arn
        EVENT_FILTER_QUEUE_URL                  = var.event_filter_queue.url
        TIMELINE_QUEUE_URL                      = var.event_timeline_queue.url
        LOG_LEVEL                               = var.log_level
        OAUTH_JWKS_URL                          = var.oauth_config.jwks_url
        OAUTH_PROXY_AUDIENCE                    = var.oauth_config.proxy_audience
        OAUTH_PROXY_CLIENT_ID                   = var.oauth_config.proxy_client_id
        OAUTH_FIRST_PARTY_CLIENT_ID             = join(",", var.oauth_config.first_party_client_id)
        OTEL_COLLECTOR_URL                      = "${var.otel_collector_config.host}:${var.otel_collector_config.port}"
        OTEL_PYTHON_FASTAPI_EXCLUDED_URLS       = "/healthcheck" # Don't generate traces for the healthcheck endpoint.
        CACHE_REPLICATION_GROUP_ID              = module.rate_limit_cache.cache_replication_group_id
        CACHE_PRIMARY_ENDPOINT                  = module.rate_limit_cache.cache_primary_endpoint
        CACHE_READER_ENDPOINT                   = module.rate_limit_cache.cache_reader_endpoint
        CACHE_PORT                              = tostring(module.rate_limit_cache.cache_port)
      } : { name = key, value = val }
    ]
    portMappings = [{
      protocol      = "tcp"
      containerPort = local.app_port
    }]
    logConfiguration = {
      logDriver = "awslogs",
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.data_api_log_group.name,
        "awslogs-region"        = var.region,
        "awslogs-stream-prefix" = "/api",
      }
    }
    ulimits = [{
      name : "nofile",
      softLimit : pow(2, 16)
      hardLimit : pow(2, 16)
    }]
  }])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
}

resource "aws_ecs_service" "data_api_service" {
  name                               = "${local.resource_prefix}-service-${var.stage}"
  cluster                            = aws_ecs_cluster.data_api_cluster.id
  task_definition                    = aws_ecs_task_definition.data_api_task_definition.arn
  desired_count                      = var.scaling_config.desired_task_count
  launch_type                        = "FARGATE"
  scheduling_strategy                = "REPLICA"
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  load_balancer {
    target_group_arn = aws_lb_target_group.data_api_target_group.arn
    container_name   = "data_api"
    container_port   = local.app_port
  }

  network_configuration {
    security_groups  = [aws_security_group.data_api_task_security_group.id]
    subnets          = var.network_config.private_subnet_ids
    assign_public_ip = false
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}

resource "aws_appautoscaling_target" "data_api_autoscaling_target" {
  resource_id        = "service/${aws_ecs_cluster.data_api_cluster.name}/${aws_ecs_service.data_api_service.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
  min_capacity       = var.scaling_config.min_task_count
  max_capacity       = var.scaling_config.max_task_count
}

resource "aws_appautoscaling_policy" "api_scaling" {
  name               = "${local.resource_prefix}-cpu-autoscaling-${var.stage}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.data_api_autoscaling_target.resource_id
  scalable_dimension = aws_appautoscaling_target.data_api_autoscaling_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.data_api_autoscaling_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value       = var.scaling_config.cpu_utilization_target
    scale_in_cooldown  = var.scaling_config.scale_in_cooldown
    scale_out_cooldown = var.scaling_config.scale_out_cooldown
  }
}

