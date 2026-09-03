O que os arquivos fazem:
generate-hash.py

Gera um hash da senha ifsp123 usando o algoritmo yescrypt ($y$), exatamente no formato do arquivo /etc/shadow do Linux. Parece preparação para inserir uma senha conhecida no sistema.
copy-fail-python.py ⚠️

É um exploit real da CVE-2026-31431 ("Copy Fail"). Ele usa uma vulnerabilidade no subsistema criptográfico do kernel Linux (AF_ALG / algif_aead) para sobrescrever o cache de página do binário su com um shellcode malicioso, ganhando privilégios de root sem precisar de senha. Isso é escalada de privilégio local.
check-copy-fail.sh

Script de reconhecimento que verifica se o sistema é vulnerável à CVE-2026-31431 — útil para um atacante identificar alvos antes de usar o exploit acima.
etc-shadow-edit.txt e log-etc-shadow-pc-school.txt

Contêm o conteúdo real (ou simulado) do /etc/shadow de um sistema — incluindo hashes de senha dos usuários root, cti e aluno. O contexto (pc-school, aluno, cti) sugere máquinas de laboratório escolar, provavelmente do IFSP.
veyon-cli.txt

Guia para parar o Veyon, que é um software de monitoramento de alunos usado em laboratórios de informática escolares. Desativá-lo remove a supervisão do professor sobre as máquinas.

Conclusão
Esse conjunto de ferramentas parece montado para: desativar o monitoramento do professor, explorar uma vulnerabilidade do kernel para virar root, e substituir senhas em máquinas de laboratório escolar.


*PASSO A PASSO*

1. copia o repositorio copia o 'copy-fail-python.py'
2. abra o terminal
3. digite 'nano a.py'
4. cole o 'copy-fail-python.py' e de ctrl + s, depois ctrl + x
5. entre no repositorio e copia 'generate-hash.py'
6. no terminal digite 'nano b.py', de ctrl + s, depois ctrl + x
7. digite no terminal 'python3 b.py' e copia o hash (senha)
8. depois digite 'python3 a.py' e depois digite 'nano /etc/shadow'
9. ao acessar a tela ache o nome cti
10. depois cole a senha no cti entre os dois pontos e de ctrl + s 
