variable "oci_tenancy_ocid" {
  type = string
}

variable "oci_compartment_id" {
  type = string
}

variable "cloudflare_api_token" {
  type = string
  sensitive = true
}

variable "cloudflare_account_id" {
  type = string
}

variable "ssh_public_key" {
  type = string
}
