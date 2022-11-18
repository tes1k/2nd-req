locals {
  services = [
    "sourcerepo.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "iam.googleapis.com",
  ]
}
  
resource "google_cloudbuild_trigger" "testing" {
  github {
    owner = "tes1k"
    name  = "tes1k/mytestrepo1"
    pull_request {
      branch = "^main$"
    }
  }
  
  

  provider = google-beta
  project = "test-project-2022-368715"
  

  description = "testing environment."
  filename = "cloudbuild.yaml"

}
