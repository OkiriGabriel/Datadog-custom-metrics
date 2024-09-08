variable "alb_name" {
type = string
default = "test-1"
}

variable "ec2_instance_id" {
type = string
default = "i-0134eb407dbabae39"
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:836768216030:loadbalancer/app/test-1/75ca5b38abba8a9e"
  port              = "80"
  protocol          = "HTTP"


  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.web_app_tg.arn}"
  }
}

resource "aws_lb_listener" "admin" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:836768216030:loadbalancer/app/test-1/75ca5b38abba8a9e"
  port              = "3000"
  protocol          = "HTTP"


  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.admin_tg.arn}"
  }
}

resource "aws_lb_listener" "backend" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:836768216030:loadbalancer/app/test-1/75ca5b38abba8a9e"
  port              = "3005"
  protocol          = "HTTP"


  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.api_server_tg.arn}"
  }
}



resource "aws_lb_target_group" "web_app_tg" {
name = "web-app-tg"
port = 80
vpc_id = "vpc-058573f6ab7547f01"
  protocol = "HTTP"
   target_type          = "instance"
health_check {
interval = 10
timeout = 5
unhealthy_threshold = 2
healthy_threshold = 3
matcher = "200"
path = "/"
}
}

resource "aws_lb_target_group" "api_server_tg" {
name = "api-server-tg"
port = 3000
   protocol = "HTTP"
vpc_id = "vpc-058573f6ab7547f01"
 target_type          = "instance"
health_check {
interval = 10
timeout = 5
unhealthy_threshold = 2
healthy_threshold = 3
matcher = "200"
path = "/health"
}
}

resource "aws_lb_target_group" "admin_tg" {
name = "admin-tg"
port = 3000
vpc_id = "vpc-058573f6ab7547f01"
  protocol = "HTTP"
   target_type          = "instance"
health_check {
interval = 10
timeout = 5
unhealthy_threshold = 2
healthy_threshold = 3
matcher = "200"
path = "/health"
}
}


resource "aws_lb_target_group_attachment" "web_app_tg_attachment" {
target_group_arn = aws_lb_target_group.web_app_tg.arn
target_id = var.ec2_instance_id
port = 80
}

resource "aws_lb_target_group_attachment" "api_server_tg_attachment" {
target_group_arn = aws_lb_target_group.api_server_tg.arn
target_id = var.ec2_instance_id
port = 3000
}

resource "aws_lb_target_group_attachment" "admin_attachment" {
target_group_arn = aws_lb_target_group.admin_tg.arn
target_id = var.ec2_instance_id
port = 3000
}
