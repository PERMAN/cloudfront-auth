variable "cloudfront_url" {
  type = string
}

variable "client_id" {
  type = string
}

variable "client_secret" {
  type      = string
  sensitive = true
}

variable "issuer" {
  type = string
}

variable "authz_endpoint" {
  type = string
}

variable "token_endpoint" {
  type = string
}

variable "jwks_uri" {
  type = string
}

variable "session_duration" {
  type = string
}

variable "encrypt_key" {
  type      = string
  sensitive = true
}