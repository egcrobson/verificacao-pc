#requires -version 5.1
<#
  VERIFICAÇÃO DE SEGURANÇA DO PC — SOMENTE LEITURA
  ------------------------------------------------
  Este script NÃO apaga, NÃO altera e NÃO baixa nada da internet.
  Ele só lê informações do Windows e, no final, salva um relatório HTML
  na sua Área de Trabalho e abre o relatório no navegador.

  Como rodar (PowerShell aberto como ADMINISTRADOR):
    powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\VerificacaoPC.ps1"

  O que ele confere:
    1. Programas que mais usam o processador e de qual pasta rodam
    2. Uso da placa de vídeo
    3. O que liga sozinho com o Windows (registro Run/RunOnce e pasta Inicializar)
    4. Serviços que não são da Microsoft
    5. Tarefas agendadas fora da pasta \Microsoft
    6. Programas rodando de AppData/Temp/ProgramData/Público e executáveis sem assinatura
    7. Conexões de rede, portas abertas e endereços de mineração no DNS
    8. Microsoft Defender: se está ligado, exclusões e histórico de ameaças
    9. Arquivo hosts e assinaturas WMI
#>

$ErrorActionPreference = 'SilentlyContinue'
$inicio = Get-Date
$Secoes = New-Object System.Collections.ArrayList
$cacheAss = @{}

$pastaSuspeita   = '(?i)\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\Public\\'
$execSuspeito    = '(?i)\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)(\.exe)?\b'
$sinaisAtaque    = '(?i)\s-e(nc|ncodedcommand)?\s|hidden|frombase64|downloadstring|downloadfile|\biex\b|invoke-expression|invoke-webrequest|https?://'
$portasMineracao = 3333,3334,3357,4444,5555,7777,14433,14444,45560,45700
$poolsMineracao  = '(?i)pool|xmr|monero|nicehash|nanopool|2miners|hashvault|c3pool|f2pool|ethermine|unmineable|herominers|kryptex|minergate|coinhive'

# ---------------------------------------------------------------- funções
function Passo([string]$t) { Write-Host "  > $t" -ForegroundColor Cyan }

function Ocultar([string]$t) {
  if (-not $t) { return $t }
  $t = $t -replace '(?i)((?:token|apikey|api_key|api-key|key|password|passwd|pwd|senha|secret|auth)\s*[=:]\s*)("[^"]*"|\S+)', '$1[oculto]'
  $t -replace '(?i)(--?(?:token|api-?key|password|senha|secret)\s+)(\S+)', '$1[oculto]'
}

function Get-ExePath([string]$cmd) {
  if (-not $cmd) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if ($c -match '^"([^"]+)"') { $c = $matches[1] }
  elseif ($c -match '(?i)^(.+?\.(exe|dll|sys|com|scr|bat|cmd|ps1|vbs|js))(\s|$)') { $c = $matches[1] }
  if ($c -like '\\?\*') { $c = $c.Substring(4) }
  if ($c -and $c -notmatch '\\|/') {
    $tent = Join-Path "$env:SystemRoot\System32" $c
    if (Test-Path -LiteralPath $tent -PathType Leaf) { $c = $tent }
  }
  return $c
}

function Get-Signer([string]$path) {
  if (-not $path) { return '(sem caminho)' }
  if ($cacheAss.ContainsKey($path)) { return $cacheAss[$path] }
  $real = $path
  if (-not (Test-Path -LiteralPath $real -PathType Leaf) -and $real -match '(?i)\\System32\\') {
    $alt = $real -ireplace '\\System32\\', '\SysWOW64\'
    if (Test-Path -LiteralPath $alt -PathType Leaf) { $real = $alt }
  }
  if (-not (Test-Path -LiteralPath $real -PathType Leaf)) { $r = '(arquivo não encontrado)' }
  else {
    $s = Get-AuthenticodeSignature -LiteralPath $real
    if (-not $s) { $r = '(erro ao ler)' }
    elseif ($s.Status -eq 'Valid' -and $s.SignerCertificate) {
      $sub = $s.SignerCertificate.Subject
      if ($sub -match '^CN="([^"]+)"') { $r = $matches[1] }
      elseif ($sub -match '^CN=([^,]+)') { $r = $matches[1] }
      else { $r = $sub }
    }
    elseif ($s.SignerCertificate) { $r = "(assinatura $($s.Status))" }
    else { $r = '(SEM ASSINATURA)' }
  }
  $cacheAss[$path] = $r
  return $r
}

function Get-Nivel([string]$path, [string]$signer, [string]$cmd) {
  if ($cmd -and $cmd -match $execSuspeito -and $cmd -match $sinaisAtaque) { return 'SUSPEITO' }
  $semAssinatura = $signer -like '(*'
  $emPastaSuspeita = $path -and ($path -match $pastaSuspeita)
  if ($semAssinatura -and $emPastaSuspeita) { return 'SUSPEITO' }
  if ($semAssinatura) { return 'CONFERIR' }
  return 'OK'
}

function Add-Secao([string]$titulo, [string]$descricao, $linhas) {
  [void]$Secoes.Add([pscustomobject]@{ Titulo = $titulo; Descricao = $descricao; Linhas = @($linhas | Where-Object { $_ }) })
}

# ---------------------------------------------------------------- início
Clear-Host
Write-Host ''
Write-Host '  VERIFICAÇÃO DE SEGURANÇA DO PC (somente leitura)' -ForegroundColor White
Write-Host '  Nada será apagado ou alterado. Pode levar alguns minutos.' -ForegroundColor Gray
Write-Host ''

$ehAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $ehAdmin) {
  Write-Host '  ATENÇÃO: o PowerShell NÃO está como administrador. Algumas partes vão ficar incompletas.' -ForegroundColor Yellow
  Write-Host ''
}

# ---------------------------------------------------------------- 1. processos
Passo 'Programas que mais usam o processador'
$protegidos = 'System','Idle','Registry','Memory Compression','Secure System','smss','csrss','wininit','winlogon','services','lsass','LsaIso',
              'svchost','MsMpEng','NisSrv','MpDefenderCoreService','SecurityHealthService','SgrmBroker','fontdrvhost','dwm','WmiPrvSE',
              'vmmem','vmmemWSL','MsSense','audiodg','spoolsv'
$linhas = Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 | ForEach-Object {
  $p = $_.Path
  if ($p) { $sig = Get-Signer $p; $niv = Get-Nivel $p $sig $null }
  else { $sig = '(protegido pelo sistema)'; $niv = if ($protegidos -contains $_.Name) { 'OK' } else { 'CONFERIR' } }
  [pscustomobject]@{ Nivel = $niv; Programa = $_.Name; PID = $_.Id; 'CPU (s)' = [math]::Round($_.CPU, 0); 'RAM (MB)' = [math]::Round($_.WorkingSet64 / 1MB, 0); Assinado = $sig; Pasta = $p }
}
Add-Secao '1. Programas que mais usam o processador' 'A coluna CPU mostra segundos acumulados desde que cada programa abriu. Lembre: alguns mineradores param quando o Gerenciador de Tarefas está aberto.' $linhas

# ---------------------------------------------------------------- 2. GPU
Passo 'Uso da placa de vídeo'
$gpu = Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine |
  Where-Object { $_.UtilizationPercentage -gt 0 -and $_.Name -match 'pid_(\d+)' } |
  ForEach-Object { [pscustomobject]@{ PID = [int]($_.Name -replace '^pid_(\d+).*', '$1'); Uso = [int]$_.UtilizationPercentage } }
$linhas = $gpu | Group-Object PID | ForEach-Object {
  $proc = Get-Process -Id $_.Name; $p = $proc.Path; $sig = Get-Signer $p
  $uso = ($_.Group | Measure-Object Uso -Sum).Sum
  $niv = Get-Nivel $p $sig $null
  if ($uso -ge 50 -and $niv -ne 'OK') { $niv = 'SUSPEITO' }
  [pscustomobject]@{ Nivel = $niv; Programa = $proc.Name; PID = $_.Name; 'GPU %' = $uso; Assinado = $sig; Pasta = $p }
} | Sort-Object 'GPU %' -Descending
Add-Secao '2. Uso da placa de vídeo agora' 'Mineradores costumam usar muito a placa de vídeo. Vazio = nenhum programa usando a placa neste momento.' $linhas

# ---------------------------------------------------------------- 3. inicialização
Passo 'O que liga sozinho com o Windows'
$chaves = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
          'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
          'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
          'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
          'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
          'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$linhas = @()
foreach ($k in $chaves) {
  if (-not (Test-Path $k)) { continue }
  $item = Get-ItemProperty $k
  foreach ($prop in $item.PSObject.Properties) {
    if ($prop.Name -like 'PS*') { continue }
    $cmd = [string]$prop.Value
    $p = Get-ExePath $cmd
    if (-not $cmd -or $p -notmatch '\\|/') { $sig = '(não aponta para programa)'; $niv = 'CONFERIR' }
    else { $sig = Get-Signer $p; $niv = Get-Nivel $p $sig $cmd }
    $linhas += [pscustomobject]@{ Nivel = $niv; Local = ($k -replace '\\Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\', ' '); Nome = $prop.Name; Assinado = $sig; Executa = (Ocultar $cmd) }
  }
}
$sh = New-Object -ComObject WScript.Shell
$pastasStartup = @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))
Get-ChildItem $pastasStartup -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
  if ($_.Extension -eq '.lnk') { $l = $sh.CreateShortcut($_.FullName); $cmd = "$($l.TargetPath) $($l.Arguments)".Trim(); $p = $l.TargetPath }
  else { $cmd = $_.FullName; $p = $_.FullName }
  $sig = Get-Signer $p
  $linhas += [pscustomobject]@{ Nivel = (Get-Nivel $p $sig $cmd); Local = 'Pasta Inicializar'; Nome = $_.Name; Assinado = $sig; Executa = (Ocultar $cmd) }
}
Add-Secao '3. O que liga sozinho com o Windows' 'Chaves Run/RunOnce do registro e pasta Inicializar. Discord, Spotify, Steam e OneDrive rodando de AppData são normais.' $linhas

# ---------------------------------------------------------------- 4. serviços
Passo 'Serviços que não são da Microsoft (pode demorar)'
$linhas = Get-CimInstance Win32_Service | ForEach-Object {
  $p = Get-ExePath $_.PathName; $sig = Get-Signer $p
  if ($sig -notmatch '^Microsoft') {
    [pscustomobject]@{ Nivel = (Get-Nivel $p $sig $_.PathName); Servico = $_.Name; Estado = $_.State; Inicio = $_.StartMode; Assinado = $sig; Executa = (Ocultar $_.PathName) }
  }
} | Sort-Object Assinado
Add-Secao '4. Serviços que não são da Microsoft' 'Vírus gosta de se instalar como serviço. Aqui só aparecem serviços que não são assinados pela Microsoft.' $linhas

# ---------------------------------------------------------------- 5. tarefas agendadas
Passo 'Tarefas agendadas fora da pasta \Microsoft'
$linhas = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $t = $_
  $acoes = @($t.Actions | ForEach-Object { if ($_.Execute) { "$($_.Execute) $($_.Arguments)".Trim() } else { "COM: $($_.ClassId)" } })
  $quando = (@($t.Triggers | ForEach-Object {
      $tipo = $_.CimClass.CimClassName -replace 'MSFT_Task', '' -replace 'Trigger', ''
      if ($_.Repetition.Interval) { "$tipo (repete $($_.Repetition.Interval))" } else { $tipo }
    }) -join ', ')
  $primeira = $t.Actions | Select-Object -First 1
  if ($primeira.Execute) {
    $p = Get-ExePath $primeira.Execute; $sig = Get-Signer $p; $niv = Get-Nivel $p $sig ($acoes -join ' ')
  }
  else {
    $pkg = (Get-ChildItem "Registry::HKEY_CLASSES_ROOT\PackagedCom\ClassIndex\$($primeira.ClassId)" | Select-Object -First 1).PSChildName
    if ($pkg) {
      $sig = "Pacote: $pkg"
      $niv = if ($pkg -match '_(cw5n1h2txyewy|8wekyb3d8bbwe)$') { 'OK' } else { 'CONFERIR' }
    }
    else {
      $srv = $null
      foreach ($r in "Registry::HKEY_CLASSES_ROOT\CLSID\$($primeira.ClassId)\InprocServer32", "Registry::HKEY_CLASSES_ROOT\CLSID\$($primeira.ClassId)\LocalServer32") {
        if (Test-Path $r) { $srv = Get-ExePath ((Get-ItemProperty $r).'(default)'); break }
      }
      $sig = Get-Signer $srv; $niv = Get-Nivel $srv $sig $null
      if ($srv) { $acoes += "-> $srv" }
    }
  }
  [pscustomobject]@{ Nivel = $niv; Tarefa = $t.TaskPath + $t.TaskName; Estado = [string]$t.State; Quando = $quando; Assinado = $sig; Executa = (Ocultar ($acoes -join ' | ')) }
}
Add-Secao '5. Tarefas agendadas fora da pasta \Microsoft' 'Esconderijo preferido de minerador: faz o vírus voltar sozinho. PT1H = a cada 1 hora, PT5M = a cada 5 minutos, P1D = todo dia.' $linhas

# ---------------------------------------------------------------- 6. pastas de usuário
Passo 'Programas rodando de pastas de usuário e temporárias'
$linhas = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match $pastaSuspeita } | Sort-Object ExecutablePath -Unique | ForEach-Object {
  $sig = Get-Signer $_.ExecutablePath
  [pscustomobject]@{ Nivel = (Get-Nivel $_.ExecutablePath $sig $_.CommandLine); Programa = $_.Name; PID = $_.ProcessId; Assinado = $sig; Pasta = $_.ExecutablePath }
}
Add-Secao '6a. Programas rodando de AppData, Temp, ProgramData ou Público' 'Discord, Spotify, OneDrive e Steam rodam daqui normalmente. O que pesa é estar SEM assinatura.' $linhas

Passo 'Executáveis e scripts sem assinatura nessas pastas (pode demorar alguns minutos)'
$ignorar = '(?i)\\Extensions\\[a-p]{32}\\|\\Packages\\Claude_|\\node_modules\\|\\Code Cache\\|\\Service Worker\\|\\GPUCache\\'
$pastas = $env:APPDATA, $env:LOCALAPPDATA, $env:TEMP, $env:ProgramData, 'C:\Users\Public', "$env:SystemRoot\Temp"
$linhas = Get-ChildItem $pastas -Recurse -File -Force -Include *.exe,*.dll,*.scr,*.ps1,*.vbs,*.bat,*.cmd,*.js,*.hta |
  Where-Object { $_.FullName -notmatch $ignorar } |
  Where-Object { $_.Extension -notin '.exe','.dll','.scr' -or (Get-AuthenticodeSignature -LiteralPath $_.FullName).Status -ne 'Valid' } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 80 | ForEach-Object {
    $niv = 'OK'
    if ($_.Extension -in '.exe','.scr','.hta') { $niv = 'CONFERIR' }
    elseif ($_.Extension -in '.ps1','.vbs','.bat','.cmd' -and $_.FullName -match '(?i)\\Temp\\|\\Users\\Public\\|\\Start Menu\\Programs\\Startup\\') { $niv = 'CONFERIR' }
    [pscustomobject]@{ Nivel = $niv; Modificado = $_.LastWriteTime.ToString('dd/MM/yyyy HH:mm'); KB = [math]::Round($_.Length / 1KB, 0); Arquivo = $_.FullName }
  }
Add-Secao '6b. Executáveis e scripts sem assinatura em pastas de usuário (80 mais recentes)' 'Arquivos .js e .dll de jogos e programas costumam não ter assinatura. Executável (.exe) sem assinatura merece uma conferida, mas não é vírus por si só.' $linhas

# ---------------------------------------------------------------- 7. rede
Passo 'Conexões de rede'
$linhas = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' } | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess; $p = $proc.Path
  $niv = 'OK'
  if ($_.RemotePort -in $portasMineracao) { $niv = 'SUSPEITO' }
  elseif ($p -and $p -match $pastaSuspeita -and ((Get-Signer $p) -like '(*')) { $niv = 'SUSPEITO' }
  [pscustomobject]@{ Nivel = $niv; Programa = $proc.Name; PID = $_.OwningProcess; Remoto = "$($_.RemoteAddress):$($_.RemotePort)"; Pasta = $p }
} | Sort-Object Programa
Add-Secao '7a. Conexões abertas com a internet' "Portas de mineração vigiadas: $($portasMineracao -join ', '). Endereços 192.168.x.x são da sua própria rede de casa." $linhas

$linhas = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' } | Sort-Object LocalPort -Unique | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess; $p = $proc.Path
  $niv = 'OK'
  if ($p -and $p -match $pastaSuspeita -and ((Get-Signer $p) -like '(*')) { $niv = 'SUSPEITO' }
  [pscustomobject]@{ Nivel = $niv; Programa = $proc.Name; Porta = $_.LocalPort; Pasta = $p }
}
Add-Secao '7b. Programas esperando conexão de fora (portas abertas)' 'Portas 135, 139, 445, 5040, 5357, 7680 e 49664+ são do próprio Windows.' $linhas

$linhas = Get-DnsClientCache | Where-Object { $_.Entry -match $poolsMineracao } | Select-Object -ExpandProperty Entry -Unique | ForEach-Object {
  [pscustomobject]@{ Nivel = 'SUSPEITO'; Endereco = $_ }
}
Add-Secao '7c. Endereços de mineração consultados recentemente (cache de DNS)' 'Vazio = o PC não procurou nenhum endereço típico de "pool" de mineração.' $linhas

# ---------------------------------------------------------------- 8. Defender
Passo 'Microsoft Defender'
$st = Get-MpComputerStatus
$pref = Get-MpPreference
$linhas = @()
if (-not $st) {
  $linhas += [pscustomobject]@{ Nivel = 'CONFERIR'; Item = 'Microsoft Defender'; Valor = 'Não foi possível ler (outro antivírus ativo ou Defender desativado)' }
}
else {
  $itens = @(
    @('Antivírus ligado', $st.AntivirusEnabled, 'SUSPEITO'),
    @('Proteção em tempo real', $st.RealTimeProtectionEnabled, 'SUSPEITO'),
    @('Monitor de comportamento', $st.BehaviorMonitorEnabled, 'SUSPEITO'),
    @('Verificação de downloads', $st.IoavProtectionEnabled, 'SUSPEITO'),
    @('Proteção contra adulteração', $st.IsTamperProtected, 'CONFERIR')
  )
  foreach ($i in $itens) {
    $linhas += [pscustomobject]@{ Nivel = $(if ($i[1]) { 'OK' } else { $i[2] }); Item = $i[0]; Valor = $(if ($i[1]) { 'Ligado' } else { 'DESLIGADO' }) }
  }
  $idadeAss = (New-TimeSpan -Start $st.AntivirusSignatureLastUpdated -End (Get-Date)).Days
  $linhas += [pscustomobject]@{ Nivel = $(if ($idadeAss -gt 7) { 'CONFERIR' } else { 'OK' }); Item = 'Assinaturas atualizadas em'; Valor = "$($st.AntivirusSignatureLastUpdated) ($idadeAss dias atrás)" }
  $fs = $st.FullScanEndTime
  if ($fs) { $dFs = (New-TimeSpan -Start $fs -End (Get-Date)).Days; $vFs = "$fs ($dFs dias atrás)" } else { $dFs = 9999; $vFs = '(nunca)' }
  $linhas += [pscustomobject]@{ Nivel = $(if ($dFs -gt 30) { 'CONFERIR' } else { 'OK' }); Item = 'Última verificação completa'; Valor = $vFs }
}
if ($pref) {
  foreach ($par in @(@('Pasta excluída', $pref.ExclusionPath), @('Programa excluído', $pref.ExclusionProcess), @('Extensão excluída', $pref.ExclusionExtension), @('IP excluído', $pref.ExclusionIpAddress))) {
    foreach ($v in @($par[1] | Where-Object { $_ })) {
      if ($v -like 'N/A*') { $linhas += [pscustomobject]@{ Nivel = 'CONFERIR'; Item = $par[0]; Valor = 'Precisa rodar como administrador para ver' }; continue }
      $nv = if ([string]$v -match $pastaSuspeita -or [string]$v -match '^[A-Za-z]:\\?$') { 'SUSPEITO' } else { 'CONFERIR' }
      $linhas += [pscustomobject]@{ Nivel = $nv; Item = $par[0]; Valor = $v }
    }
  }
  if (-not ($pref.ExclusionPath -or $pref.ExclusionProcess -or $pref.ExclusionExtension -or $pref.ExclusionIpAddress)) {
    $linhas += [pscustomobject]@{ Nivel = 'OK'; Item = 'Exclusões'; Valor = 'Nenhuma exclusão cadastrada' }
  }
  if ($pref.MAPSReporting -eq 0) { $linhas += [pscustomobject]@{ Nivel = 'CONFERIR'; Item = 'Proteção na nuvem'; Valor = 'DESLIGADA' } }
}
$ameacas = Get-MpThreat
$deteccoes = Get-MpThreatDetection
if ($deteccoes) {
  foreach ($d in ($deteccoes | Sort-Object InitialDetectionTime -Descending)) {
    $nome = ($ameacas | Where-Object ThreatID -eq $d.ThreatID | Select-Object -First 1).ThreatName
    $linhas += [pscustomobject]@{ Nivel = 'CONFERIR'; Item = "Ameaça detectada em $($d.InitialDetectionTime)"; Valor = "$nome | removida: $($d.ActionSuccess) | $(($d.Resources | Select-Object -First 3) -join ' ; ')" }
  }
}
else { $linhas += [pscustomobject]@{ Nivel = 'OK'; Item = 'Histórico de ameaças'; Valor = 'Nenhuma ameaça registrada' } }
Add-Secao '8. Microsoft Defender' 'Vírus costuma desligar o antivírus ou se cadastrar nas EXCLUSÕES para não ser visto.' $linhas

# ---------------------------------------------------------------- 9. hosts e WMI
Passo 'Arquivo hosts e assinaturas WMI'
$linhas = @()
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and $_.Trim() -notlike '#*' } | ForEach-Object {
  $linhas += [pscustomobject]@{ Nivel = 'CONFERIR'; Tipo = 'hosts'; Nome = $_.Trim(); Detalhe = 'Linha ativa no arquivo hosts (redireciona um endereço)' }
}
$wmiPadrao = 'SCM Event Log Filter', 'SCM Event Log Consumer', 'BVTFilter', 'BVTConsumer'
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | ForEach-Object {
  $linhas += [pscustomobject]@{ Nivel = $(if ($wmiPadrao -contains $_.Name) { 'OK' } else { 'CONFERIR' }); Tipo = 'WMI filtro'; Nome = $_.Name; Detalhe = $_.Query }
}
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ForEach-Object {
  $classe = $_.CimClass.CimClassName
  $det = switch ($classe) {
    'CommandLineEventConsumer'  { "Executa: $($_.CommandLineTemplate) $($_.ExecutablePath)" }
    'ActiveScriptEventConsumer' { $s = "$($_.ScriptText)"; if ($s.Length -gt 300) { $s = $s.Substring(0, 300) + ' ...(cortado)' }; "Script: $s" }
    default { $classe }
  }
  $nv = if ($wmiPadrao -contains $_.Name) { 'OK' } elseif ($classe -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') { 'SUSPEITO' } else { 'CONFERIR' }
  $linhas += [pscustomobject]@{ Nivel = $nv; Tipo = "WMI ação ($classe)"; Nome = $_.Name; Detalhe = (Ocultar $det) }
}
Add-Secao '9. Arquivo hosts e assinaturas WMI' 'Lugares onde vírus se esconde para redirecionar sites ou voltar depois de removido. "SCM Event Log" é padrão do Windows.' $linhas

# ---------------------------------------------------------------- relatório
Passo 'Montando o relatório'
function HtmlSafe($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }

$todas = @($Secoes | ForEach-Object { $_.Linhas })
$nS = @($todas | Where-Object { $_.Nivel -eq 'SUSPEITO' }).Count
$nC = @($todas | Where-Object { $_.Nivel -eq 'CONFERIR' }).Count
$nO = @($todas | Where-Object { $_.Nivel -eq 'OK' }).Count

if ($nS -gt 0) { $classeV = 'suspeito'; $veredito = "Foram encontrados $nS item(ns) SUSPEITO(S). Não apague nada por conta própria: leve este relatório para análise e rode a Verificação offline do Microsoft Defender." }
elseif ($nC -gt 0) { $classeV = 'conferir'; $veredito = "Nenhum item suspeito. Há $nC item(ns) para conferir, listados logo abaixo. Em geral são sobras de programas ou arquivos sem assinatura, não vírus." }
else { $classeV = 'ok'; $veredito = 'Nenhum problema encontrado.' }

$sbLista = New-Object System.Text.StringBuilder
foreach ($s in $Secoes) {
  foreach ($l in $s.Linhas) {
    if ($l.Nivel -ne 'OK') {
      $resumo = (@($l.PSObject.Properties | Where-Object { $_.Name -ne 'Nivel' -and "$($_.Value)" } | Select-Object -First 3 | ForEach-Object { "$($_.Value)" }) -join ' | ')
      [void]$sbLista.Append("<li><span class='nv $($l.Nivel.ToLower())'>$(HtmlSafe $l.Nivel)</span> <b>$(HtmlSafe ($s.Titulo -replace '^\S+\s',''))</b>: $(HtmlSafe $resumo)</li>")
    }
  }
}
$lista = if ($sbLista.Length) { "<h2>Itens para olhar</h2><ul class='lista'>$($sbLista.ToString())</ul>" } else { '' }

$sb = New-Object System.Text.StringBuilder
foreach ($s in $Secoes) {
  [void]$sb.Append("<section><h2>$(HtmlSafe $s.Titulo)</h2><p class='desc'>$(HtmlSafe $s.Descricao)</p>")
  if ($s.Linhas.Count -eq 0) { [void]$sb.Append("<p class='vazio'>Nada encontrado.</p>") }
  else {
    $cols = @($s.Linhas | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique)
    [void]$sb.Append('<div class="tw"><table><thead><tr>')
    foreach ($c in $cols) { [void]$sb.Append("<th>$(HtmlSafe $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($l in $s.Linhas) {
      [void]$sb.Append('<tr>')
      foreach ($c in $cols) {
        $v = $l.$c
        if ($c -eq 'Nivel') { [void]$sb.Append("<td><span class='nv $(([string]$v).ToLower())'>$(HtmlSafe $v)</span></td>") }
        else { [void]$sb.Append("<td>$(HtmlSafe $v)</td>") }
      }
      [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
  }
  [void]$sb.Append('</section>')
}

$duracao = [math]::Round((New-TimeSpan -Start $inicio -End (Get-Date)).TotalMinutes, 1)
$avisoAdmin = if ($ehAdmin) { '' } else { "<p class='aviso'>Atenção: rodado SEM permissão de administrador. Algumas partes (serviços, exclusões do Defender, processos protegidos) podem estar incompletas.</p>" }
$os = (Get-CimInstance Win32_OperatingSystem).Caption

$html = @"
<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatório de Segurança do PC</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--tx:#1d2330;--mut:#5d6575;--bd:#e3e6eb;--ok:#1f7a3f;--okb:#e3f4e8;--cf:#8a5a00;--cfb:#fff2d6;--su:#b3261e;--sub:#fde3e1}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1d2026;--tx:#e7e9ee;--mut:#9aa1ad;--bd:#2e323a;--ok:#7ed69b;--okb:#1d3526;--cf:#f0c060;--cfb:#3a2f14;--su:#ff8a80;--sub:#40201e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 6px}
.meta{color:var(--mut);font-size:13px}
.veredito{margin:18px 0;padding:16px 18px;border-radius:10px;font-weight:600}
.veredito.ok{background:var(--okb);color:var(--ok)}.veredito.conferir{background:var(--cfb);color:var(--cf)}.veredito.suspeito{background:var(--sub);color:var(--su)}
.cont{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0}.cont div{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:10px 16px;min-width:120px}
.cont b{font-size:22px;display:block}
.aviso{background:var(--cfb);color:var(--cf);padding:10px 14px;border-radius:8px}
.desc{color:var(--mut);margin:0 0 8px;font-size:14px}.vazio{color:var(--mut);font-style:italic}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--bd);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:7px 10px;border-bottom:1px solid var(--bd);text-align:left;vertical-align:top;word-break:break-word}
th{background:var(--bg);position:sticky;top:0}tr:last-child td{border-bottom:0}
.nv{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:700;white-space:nowrap}
.nv.ok{background:var(--okb);color:var(--ok)}.nv.conferir{background:var(--cfb);color:var(--cf)}.nv.suspeito{background:var(--sub);color:var(--su)}
.lista{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 12px 12px 32px}.lista li{margin:4px 0}
footer{margin-top:32px;color:var(--mut);font-size:13px}
</style></head><body><main>
<h1>Relatório de Segurança do PC</h1>
<div class="meta">Computador: $(HtmlSafe $env:COMPUTERNAME) &middot; Usuário: $(HtmlSafe $env:USERNAME) &middot; $(HtmlSafe $os) &middot; Gerado em $(Get-Date -Format 'dd/MM/yyyy HH:mm') &middot; Duração: $duracao min</div>
$avisoAdmin
<div class="veredito $classeV">$(HtmlSafe $veredito)</div>
<div class="cont"><div><b style="color:var(--su)">$nS</b>Suspeito</div><div><b style="color:var(--cf)">$nC</b>Conferir</div><div><b style="color:var(--ok)">$nO</b>OK</div></div>
$lista
$($sb.ToString())
<footer>
<p><b>Como ler:</b> OK = normal. CONFERIR = vale olhar, mas não é vírus por si só. SUSPEITO = padrão típico de vírus (sem assinatura em pasta de usuário, porta de mineração, PowerShell escondido, exclusão no antivírus etc.).</p>
<p>Este relatório foi gerado somente com leitura: nada foi apagado ou alterado. Ele <b>não substitui um antivírus</b>. Para completar: rode a verificação completa do Microsoft Defender, a Verificação offline do Defender (reinicia o PC) e, se quiser uma segunda opinião, o Malwarebytes gratuito.</p>
</footer>
</main></body></html>
"@

$desk = [Environment]::GetFolderPath('Desktop')
$arq = Join-Path $desk ("Relatorio_Seguranca_PC_" + (Get-Date -Format 'yyyy-MM-dd_HHmm') + '.html')
Set-Content -Path $arq -Value $html -Encoding UTF8

Write-Host ''
Write-Host "  Pronto! Suspeito: $nS | Conferir: $nC | OK: $nO" -ForegroundColor Green
Write-Host "  Relatório salvo em: $arq" -ForegroundColor Green
Write-Host ''
Start-Process $arq
