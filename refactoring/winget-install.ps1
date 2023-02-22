Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
$env:PSModulePath += ";$([System.IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), 'PowerShell\Scripts'))"

Invoke-Command -ScriptBlock {
    Start-Process powershell.exe -ArgumentList "-Command `"`Install-Script winget-install -Scope AllUsers -Confirm:`$false; winget-install; winget install -h Microsoft.Powershell`""
} -NoNewScope
