terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
      version = ">= 4.0.0"
    }
    cloudflare = {
      source = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "oci" {
  tenancy_ocid = var.oci_tenancy_ocid
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

resource "oci_core_instance" "vm" {
  availability_domain = "dummy"
  compartment_id      = var.oci_compartment_id
  shape               = "VM.Standard.A1.Flex"
  
  shape_config {
    ocpus = 4
    memory_in_gbs = 24
  }
  
  create_vnic_details {
    subnet_id = "dummy_subnet"
    assign_public_ip = true
  }
  
  metadata = {
    ssh_authorized_keys = var.ssh_public_key
  }
}

resource "cloudflare_r2_bucket" "assets" {
  account_id = var.cloudflare_account_id
  name       = "pkintel-assets"
}

resource "cloudflare_pages_project" "frontend" {
  account_id        = var.cloudflare_account_id
  name              = "pkintel-web"
  production_branch = "main"
}
