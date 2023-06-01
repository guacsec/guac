variable "GO_LDFLAGS" {
  default = "-w -s"
}

variable "IMAGE_TAG" {
  default = "latest"
}

group "default" {
  targets = ["build"]
}

target "build" {
  dockerfile = "dockerfiles/Dockerfile"
  args = {
    GO_LDFLAGS = "${GO_LDFLAGS}"
  }
}

target "cross" {
  inherits = ["build"]
  platforms = ["linux/amd64", "linux/arm64", "linux/arm", "darwin/amd64", "darwin/arm64"]
  tags = ["ghcr.io/tuananh/guac:${IMAGE_TAG}"]
}
