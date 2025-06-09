# Exercicio 1 - Criar ficheiro binário capaz de ler o conteudo de um ficheiro passado como argumento e imprimir no terminal.
:'
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Erro: argumento inválido. Forneça o nome do ficheiro.\n");
        return 1;
    }

    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Erro ao abrir o ficheiro");
        return 1;
    }

    char ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }

    fclose(file);
    return 0;
}

'
# Exercicio 2 - Criar utilizador userssi
sudo useradd userssi

# Exercicio 3 - Alterar dono do ficheiro braga.txt para userssi
sudo chown userssi braga.txt

# Exercicio 4 - Correr o script com o utilizador normal 
./read_file braga.txt
:'                                                                                           
Erro ao abrir o ficheiro: Permission denied
'
# Exercicio 5 - Defina a permissão de setuid para o ficheiro executável.
sudo chmod u+s read_file

# Exercicio 6 - Correr o script e comentar o resultado obtido.
./read_file braga.txt
:'
Braga é conhecida pelo seu centro histórico.
Braga é uma cidade muito bonita e com um bom pastel de nata.
'
#Agora o utilizador normal consegue ler o ficheiro braga.txt, pois o ficheiro é executado com as permissões do dono do ficheiro.
#O dono do ficheiro é o utilizador userssi, que tem permissões de leitura no ficheiro braga.txt.
