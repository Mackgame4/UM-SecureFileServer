:'
Comandos Relevantes
id, groups
sudo (para uso com os comandos abaixo, revistar também os comandos chown e chgrp)
adduser, deluser, usermod
groupadd, groupdel, groupmod, groupmems
passwd (e gpasswd)
su (para inciar uma sessão associada a um outro utilizador)
sudo (para executar um comando como outro utilizador)
'


#Exercicio 0 (observar conteudo do ficheiro /etc/passwd e /etc/group)
cat /etc/passwd
cat /etc/group



#Exercicio 1 (criar utilizadores afonsoSSI e fabioSSI)
sudo useradd afonsoSSI
sudo useradd fabioSSI
sudo useradd andreSSI

#Exercicio 2 ( criar grupo-ssi e adicionar os utilizadores afonsoSSI, fabioSSI e andreSSI)
sudo groupadd grupo-ssi
sudo usermod -a -G grupo-ssi afonsoSSI
sudo usermod -a -G grupo-ssi fabioSSI
sudo usermod -a -G grupo-ssi andreSSI

#Exercicio 3  (criar grupo par-ssi e adicionar os utilizadores afonsoSSI e fabioSSI)
sudo groupadd par-ssi
sudo usermod -a -G par-ssi afonsoSSI
sudo usermod -a -G par-ssi fabioSSI

#Exercicio 4 - Após a execução dos comandos acima, verificar o conteúdo dos ficheiros /etc/passwd e /etc/group. Qual a diferenca entre o executado no exercicio 0 e agora?
echo "Após a execução deste script, as diferenças nos ficheiros são as seguintes:"
echo "1. O ficheiro /etc/passwd agora contém as entradas dos novos utilizadores criados (afonsoSSI, fabioSSI, andreSSI )."
echo "2. O ficheiro /etc/group agora contém as entradas dos novos grupos (grupo-ssi, par-ssi) e os utilizadores associados a cada grupo."

#Exercicio 5 - Alterar dono do ficheiro braga.txt para afonsoSSI
sudo chown afonsoSSI braga.txt
#Agora, ao executar cat, o ficheiro braga.txt não pode ser lido, pois o utilizador atual não tem permissões de leitura.


#Exercicio 6 - iniciar sessão como afonsoSSI e verificar se é possivel editar o ficheiro braga.txt
echo "Agora vamos iniciar uma sessão como afonsoSSI e verificar se é possível editar o ficheiro braga.txt"
su afonsoSSI
# Verificamos que o utilizador afonsoSSI consegue editar o ficheiro braga.txt
exit

#Exercicio 7 - Execute os comandos id e groups e comente o resultado impresso no terminal.
echo "Agora vamos executar os comandos id e groups para verificar as informações do utilizador atual."
id
:'
uid=1001(afonsoSSI) gid=1001(afonsoSSI) groups=1001(afonsoSSI),1003(grupo-ssi),1005(par-ssi)
'
groups
:'
afonsoSSI grupo-ssi par-ssi
'

#Exercicio 8 - Leia o conteúdo do ficheiro braga.txt. Observou alguma diferença?.
:'
Agora a leitura do ficheiro braga.txt é possivel, devido ao utilizador no qual demos login ser o dono do ficheiro.
'

#Exercicio 9 - Mude para a diretoria dir2 e comente o resultado impresso no terminal.
cd dir2
:'
bash: cd: dir2/: Permission denied
Não foi possível mudar para a diretoria dir2, pois o utilizador atual não tem permissões de execução na diretoria, visto que na secção anterior nos foi pedido para executar o comando chmod 740 dir2.
'

