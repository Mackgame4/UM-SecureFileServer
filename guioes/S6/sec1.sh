
#No chmod, o primeiro argumento é o dono, o segundo é o grupo e o terceiro é os outros.
#O chmod pode ser usado de duas formas, a primeira é a forma simbólica e a segunda é a forma octal.
#Na forma simbólica, o chmod é usado da seguinte forma:
#chmod [ugoa][+-=][rwx] ficheiro
#Onde:
#u - dono
#g - grupo
#o - outros
#a - todos
#+ - adicionar permissão
#- - remover permissão
#= - definir permissão
#r - leitura
#w - escrita


#Na forma octal, o chmod é usado da seguinte forma:
#chmod [0-7][0-7][0-7] ficheiro
#Onde:
#O primeiro número é as permissões do dono
#O segundo número é as permissões do grupo
#O terceiro número é as permissões dos outros
#O número é a soma das permissões, onde:
#4 - leitura
#2 - escrita
#1 - execução



# Exercicio 1 
echo "Lisboa é a capital de Portugal." > lisboa.txt                                                                                                                ✔  8s  09:19:54 
echo "Porto é uma cidade no norte de Portugal." > porto.txt
echo "Braga é conhecida pelo seu centro histórico." > braga.txt

# Exercício 2 (verificar permissões do ficheiro lisboa.txt)
ls -l lisboa.txt

# Exercício 3 (permissão de leitura e escrita para todos os utilizadores)
chmod a+rw lisboa.txt

#Exercicio 4 (alterar porto.txt de modo a que o  DONO tenha permissoes de leitura e execucao mas nao de escrita)
chmod u-w porto.txt
chmod u+rx porto.txt

#Exercicio 5 (alterar braga.txt de modo a que apenas o dono tenha permissoes de leitura, grupos e outros nao tem permissoes de leitura)
chmod 700 braga.txt


#Exericio 6 (criar dir1 e dir2 e verificar permissoes)
mkdir dir1
mkdir dir2
ls -ld dir1 dir2

#Exercicio 7 (remover permissoes de  execucao da diretoria exceto para o dono)
chmod 740 dir1
chmod 740 dir2



