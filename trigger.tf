locals {
  services = [
    "sourcerepo.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "iam.googleapis.com",
  ]
}
resource "google_cloudbuild_trigger" "build-trigger" {

  trigger_template {
    branch_name = "main"
    repo_name   = "tes1k/mytestrepo1"
  }
  provider = google-beta
  project = "test-project-2022-368715"
  

  description = "testing environment."
  filename = "cloudbuild.yaml"

}
