# Verificação de Segurança do PC

Script em PowerShell que faz uma **triagem de segurança somente leitura** num PC com Windows, procurando sinais de minerador de criptomoeda, trojan e outros vírus. No final, ele gera um **relatório HTML** na Área de Trabalho e abre no navegador.

> **Somente leitura:** o script não apaga, não altera e não baixa nada da internet. A única coisa que ele cria é o arquivo do relatório.

## O que ele confere

| # | Verificação | Por que importa |
|---|---|---|
| 1 | Programas que mais usam o processador e de qual pasta rodam | Mineradores consomem muito processador |
| 2 | Uso da placa de vídeo | Muitos mineradores usam só a placa de vídeo |
| 3 | O que liga sozinho com o Windows (registro Run/RunOnce e pasta Inicializar) | É assim que o vírus volta depois de reiniciar |
| 4 | Serviços que não são da Microsoft, com a assinatura de cada um | Vírus gosta de se instalar como serviço |
| 5 | Tarefas agendadas fora da pasta `\Microsoft` | Esconderijo preferido de minerador |
| 6 | Programas rodando de AppData, Temp, ProgramData ou Público, e executáveis sem assinatura nessas pastas | Lugar típico de vírus instalado sem permissão de administrador |
| 7 | Conexões de rede, portas abertas e endereços de "pool" de mineração no cache de DNS | Portas como 3333, 4444, 5555, 7777 e 14444 são usadas por mineradores |
| 8 | Microsoft Defender: se está ligado, exclusões e histórico de ameaças | Vírus costuma desligar o antivírus ou se cadastrar nas exclusões |
| 9 | Arquivo `hosts` e assinaturas WMI | Usados para redirecionar sites ou voltar depois de removido |

Cada item recebe um nível:

- **OK**: normal.
- **CONFERIR**: vale olhar, mas não é vírus por si só (sobra de programa, arquivo sem assinatura...).
- **SUSPEITO**: padrão típico de vírus (programa sem assinatura em pasta de usuário, porta de mineração, PowerShell escondido, exclusão no antivírus etc.).

Senhas, tokens e chaves que aparecem em linhas de comando são trocados por `[oculto]` no relatório.

## Como usar

1. Baixe o arquivo `VerificacaoPC.ps1` (por exemplo, para a pasta **Downloads**).
2. Abra o **PowerShell como administrador** (menu Iniciar → digite "PowerShell" → botão direito → *Executar como administrador*).
3. Rode:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\VerificacaoPC.ps1"
```

O `-ExecutionPolicy Bypass` vale só para essa execução e não muda a configuração do PC.

A verificação leva de 2 a 5 minutos. Ao terminar, o relatório `Relatorio_Seguranca_PC_AAAA-MM-DD_HHMM.html` é salvo na Área de Trabalho e aberto no navegador.

Sem administrador o script também roda, mas algumas partes (serviços, exclusões do Defender, processos protegidos) ficam incompletas. O relatório avisa quando isso acontece.

## Coisas normais que assustam e não são vírus

- **Processo Ocioso do Sistema** usando "muito" processador (é o tempo livre do processador).
- **Antimalware Service Executable** (`MsMpEng`): é o próprio Microsoft Defender.
- **svchost** rodando de `C:\Windows\System32`.
- **Discord, Spotify, Steam e OneDrive** rodando de `AppData`.
- Conexões com endereços `192.168.x.x`: são aparelhos da sua própria rede de casa.

## Limites

Esta é uma **triagem**, não um antivírus. Ela olha onde os vírus costumam se esconder, mas não analisa o conteúdo de cada arquivo. Para completar a verificação:

1. Rode a **verificação completa** do Microsoft Defender.
2. Rode a **Verificação offline do Microsoft Defender** (ela reinicia o PC).
3. Para uma segunda opinião, use o **Malwarebytes** gratuito.

## Privacidade

O **relatório gerado** mostra o nome do computador, o usuário do Windows e os programas instalados. Não publique o relatório. O `.gitignore` deste repositório já impede que arquivos `Relatorio_*.html` sejam enviados por engano.

## Requisitos

- Windows 10 ou 11
- Windows PowerShell 5.1 (já vem com o Windows) ou PowerShell 7
