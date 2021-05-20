# Trabalho Certificados Digitais

## Compilação e execução:

Para execução do programa é necessário ter instalado a biblioteca "PyCrypto", "hashlib" e a biblioteca "time", todas elas são instaladas a partir do pip. O código está todo em python e em apenas um arquivo, logo é necessário apenas ter o python em sua versão mais atualizada instalada e compilar/executar o arquivo "certificados.py".

## Utilização:

A partir do menu é possível realizar as 4 ações que o trabalho pede:

 1 - Gerar Certificicado : Para gerar o certificado é necessário fornecer as credenciais que estarão presentes no mesmo. A partir disso o programa criará o certificado que ficará salvo no arquivo "cert_credenciais.cert" e as chaves publica "credenciais_pub.pem" e privada "credenciais_priv.pem".

 2 - Assinar documentos: para assinar documentos é necessário entrar com sua credencial assim o programa irá pesquisar o certificar relacionado a ela. O programa então retornará uma lista dos arquivos "txt" na pasta e você deve escolher um deles (a partir do indice retornado pelo programa) para assinar e escolherá um nome para o arquivo txt assinado.

 3 - Verificar Assinatura: é necessário informar o indice do arquivo a ser verificado e então o programa testará a assinatura com todos os certificados presentes na pasta.

 4 - Gerar certificado com assinatura de outro: informe as credenciais para o novo certificado e após isso informe as credenciais do certificado que será utilizado na assinatura, se o programa encontrar o certificado e a chave privada do assinante o novo certificado será gerado no mesmo padrão dos autoassinados.

 É necessário lembrar que na linha 17 é definida a pasta onde serão salvos os certificados e documentos assinados. Essa pasta será usada também na hora de encontrar tanto as chaves, quanto os arquivos para se assinar ou validar a assinatura.