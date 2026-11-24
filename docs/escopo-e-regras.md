# Autorização, escopo e regras de engajamento

| Item | Definição |
|---|---|
| Autorizado | ESP32 DevKit simulado no Wokwi for VS Code (projeto próprio), firmware NexaSense compilado pela avaliadora, rede virtual Wokwi-GUEST, broker MQTT e servidor OTA **locais** (`127.0.0.1`, alcançados via `host.wokwi.internal`) |
| Fora do escopo | qualquer dispositivo real de terceiros, redes da faculdade/residencial, qualquer serviço ou broker externo, a infraestrutura do Wokwi |
| Testes “físicos” | UART0 e analisador lógico virtuais; demais interfaces analisadas de forma estática/documental (ver `docs/limitacoes-ambiente-virtual.md`) |
| Proibido | negação de serviço, varredura de portas, qualquer teste contra serviços de terceiros, publicar dados pessoais |
| Critérios de parada | qualquer sinal de tráfego saindo do `127.0.0.1`/gateway do Wokwi para fora do notebook |
| Dados sensíveis | credenciais mascaradas em logs; arquivos brutos em `*/evidence/raw/` fora do repositório; prints com senha borrada |
| Responsável | Camila Cesco Ferreira (RA 134666) — Ciência da Computação, 6º semestre — Hardware Hacking (IoT) |
| Autorização | Ambiente 100% local e próprio (sem serviço externo), portanto não depende de autorização de terceiros |
