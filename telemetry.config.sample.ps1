# Copy to telemetry.config.ps1 and fill values to enable uploads.
$RootFixTelemetry = @{
  EnableEmail        = $false
  GmailFrom          = 'you@gmail.com'
  GmailTo            = 'you@gmail.com'
  GmailAppPassword   = ''

  EnableGitHubUpload = $false
  GitHubToken        = ''
  GitHubOwner        = 'JrPetersonjr'
  GitHubRepo         = 'SnakeInMyBoot'
  GitHubBranch       = 'master'
  GitHubPathPrefix   = 'client-logs'
}
