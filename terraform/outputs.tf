output "vm_public_ip" {
  value = oci_core_instance.vm.public_ip
}

output "r2_bucket_name" {
  value = cloudflare_r2_bucket.assets.name
}

output "pages_url" {
  value = cloudflare_pages_project.frontend.domains[0]
}
