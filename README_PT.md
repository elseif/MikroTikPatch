[![Patch Mikrotik RouterOS 6.x](https://github.com/elseif/MikroTikPatch/actions/workflows/mikrotik_patch_6.yml/badge.svg)](https://github.com/elseif/MikroTikPatch/actions/workflows/mikrotik_patch_6.yml)  
[![Patch Mikrotik RouterOS 7.x](https://github.com/elseif/MikroTikPatch/actions/workflows/mikrotik_patch_7.yml/badge.svg)](https://github.com/elseif/MikroTikPatch/actions/workflows/mikrotik_patch_7.yml)

# Patch para MikroTik RouterOS [[中文](README.md)]
[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](./LICENSE)
[![CoC:WTFCoC](https://img.shields.io/badge/CoC-WTFCoC-brightgreen.svg)](./CODE_OF_CONDUCT.md)

### [[Discord](https://discord.gg/keV6MWQFtX)] [[Telegram](https://t.me/mikrotikpatch)] [[Keygen (Bot do Telegram)](https://t.me/ROS_Keygen_Bot)]

### Baixe a [ISO modificada mais recente](https://github.com/elseif/MikroTikPatch/releases/latest), instale e aproveite.
### A imagem CHR suporta modo de boot tanto BIOS quanto UEFI.

### Suporte a atualização online, licença online, backup em nuvem e DDNS em nuvem

![](image/install.png)  
![](image/routeros.png)

### Renovar a licença para x86 v6.x  
![](image/renew_v6.png)

### Renovar a licença para CHR  
![](image/renew.png)


![](image/arm.png)  
![](image/mips.png)

## Como usar o shell
```bash
instale o pacote option-{versão}.npk  
Execute `/sh` no terminal para entrar no Shell.
```

## Como licenciar o RouterOS
```bash
Após instalar o pacote `option-{version}.npk`, reinicie o dispositivo. A licença será ativada automaticamente.
Imagens CHR suportam ativação de licença online.
```

## Como usar o Python 3
```bash
instale o pacote python3-{versão}.npk  
Execute `/sh` no terminal para entrar no Shell.
execute `python -V`
```

### npk.py  
```bash
Assina, verifica, cria e extrai arquivos .npk
```

### patch.py  
```bash
Altera a chave pública e assina arquivos .npk
```
### Como ativar o modo container sem reiniciar fisicamente
```bash
1. Instale o pacote `option.npk`.
2. Abra o terminal e execute: `system/device-mode/update container=yes`
3. Abra um novo terminal e execute: `system/shell cmd="reboot -f"`
```
## Thanks for sponsoring
[ZMTO](https://console.zmto.com/)

## Todos os patches são aplicados automaticamente com [GitHub Actions](https://github.com/elseif/MikroTikPatch/blob/main/.github/workflows/)
