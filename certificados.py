#Trabalho de Certificados - Segurança
#O sistema deve ser capaz de:
#
#A. Assinar documentos digitalmente, a partir de uma chave privada e um certificado associado.
#
#B. Gerar certificados de dois tipos:
#1. Certificados autoassinados.
#2. Certificados assinados com uma chave associada a um certificado preexistente.
#
#C. De posse de um conjunto de certificados, verificar se um documento assinado digitalmente, é válido.
import os
from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
from hashlib import sha512
import time
#pasta onde deseja salvar os certificados/documentos que queira assinar
pasta = '.'

def assinar():
    caminhos = [os.path.join(pasta, nome) for nome in os.listdir(pasta)]
    print("Quais são as suas credenciais?")
    credencial = input()
    arquivos = [arq for arq in caminhos if arq.endswith(credencial+ '_priv' + ".pem")]
    if arquivos == []:
        print("Não encontramos chaves compatíveis com suas credenciais")
        return
    else:
        print("Chave encontrada: " + arquivos[0])
        arq_key = arquivos[0]
    arquivos = [arq for arq in caminhos if arq.lower().endswith(".txt")]
    if arquivos == []:
        print("SEM ARQUIVOS TXT NO DIRETÓRIO PARA ASSINAR")
        return
    print("Qual arquivo deseja assinar?")
    print(arquivos)
    arqv = open(arquivos[int(input()) - 1],'r')
    linhas = arqv.readlines()
    conteudo = ''
    for lin in linhas:
        conteudo = conteudo + lin
    conteudo = conteudo.encode('utf-8')
    key = RSA.importKey(open(arq_key,'r').read())
    hash = int.from_bytes(sha512(conteudo).digest(), byteorder='big')
    assig = key.sign(hash,'')
    print("Nome do arquivo assinado:")
    arq_assin = open(pasta +'/' +input() + '.txt','w')
    arq_assin.write(conteudo.decode('utf-8') + "\n----Assinatura---- \nCredenciais: " + credencial + "\nAssig{" + str(assig) + '}')
    print("ARQUIVO ASSINADO COM SUCESSO!!")
    


def gerar_certificados():
    print('Digite suas credenciais:')
    cred = input()
    pool = RandomPool(384)
    pool.stir()
    randfunc = pool.get_bytes
    N = 1024 #tamanho da chave
    K = ""
    key = RSA.generate(N, randfunc)
    k_arq = open(pasta +'/' +cred + '_priv' + '.pem','wb')
    k_arq.write(key.exportKey('PEM'))
    k_arq.close()
    kp_arq = open(pasta +'/' +cred + '_pub' + '.pem','wb')
    kp_arq.write(key.publickey().exportKey('PEM'))
    kp_arq.close()
    #print(f"Public key:  (n={hex(key.n)}, e={hex(key.e)})")
    #print(f"Private key: (n={key.n}, d={hex(key.d)})")
    assi = ("Credenciais:" +cred +'|' + "\n" + f"Public key:(n={hex(key.n)}, e={hex(key.e)})" + "\n").encode("utf-8")
    hash = int.from_bytes(sha512(assi).digest(), byteorder='big')
    ass_cert = key.sign(hash,K)
    f = open(pasta +'/cert_'+cred +'.cert','w')
    f.write("Credenciais:" +cred +'|' + "\n" + f"Public key:(n={hex(key.n)}, e={hex(key.e)})" + '\n' +str(ass_cert))
    f.close()
    
    ##################################### VERIFICAÇÃO
    
    f = open(pasta +'/cert_'+cred +'.cert','r')
    linhas = f.readlines()
    teste = (linhas[0] + linhas[1]).encode('utf-8')
    hash = int.from_bytes(sha512(teste).digest(), byteorder='big')
    ne = linhas[1].split('=')
    n = int(ne[1].strip(", e"),16)
    e = int(ne[2].strip(")\n"),16)
    tt = linhas[2].lstrip("(").strip(",)")
    newtuple = (int(tt),)
    pub_key = RSA.construct((n, e))
    hash_desc = pub_key.verify(hash,newtuple)
    if hash_desc == True :
        print("CERTIFICADO VALIDADO COM SUCESSO!!")
    else:
        print("CERTIFICADO NÃO VALIDADO COM SUCESSO!!")
        cmd = 'rm cert_'+cred +'.cert'
        os.system(cmd)

    
def gerar_assinados():
    print('Digite suas credenciais:')
    cred = input()
    pool = RandomPool(384)
    pool.stir()
    randfunc = pool.get_bytes
    N = 1024 #tamanho da chave
    K = ""
    key = RSA.generate(N, randfunc)
    k_arq = open(pasta + '/' + cred + '_priv' + '.pem','wb')
    k_arq.write(key.exportKey('PEM'))
    k_arq.close()
    kp_arq = open(pasta + '/' + cred + '_pub' + '.pem','wb')
    kp_arq.write(key.publickey().exportKey('PEM'))
    kp_arq.close()
    #print(f"Public key:  (n={hex(key.n)}, e={hex(key.e)})")
    #print(f"Private key: (n={key.n}, d={hex(key.d)})")
    caminhos = [os.path.join(pasta, nome) for nome in os.listdir(pasta)]
    print("Quais são as credenciais do assinante?")
    credencial = input()
    arquivos = [arq for arq in caminhos if arq.lower().endswith(credencial+ '_priv' + ".pem")]
    if arquivos == []:
        print("Não encontramos chaves compatíveis com essas credenciais")
        return
    else:
        print("Chave encontrada: " + arquivos[0])
        arq_key = arquivos[0]
    key2 = RSA.importKey(open(arq_key,'r').read())
    assi = ("Credenciais:" +cred +'|' + "\n" + f"Public key:(n={hex(key.n)}, e={hex(key.e)})" + "\n" + "Credenciais assinante:" + credencial + '\n').encode("utf-8")
    hash = int.from_bytes(sha512(assi).digest(), byteorder='big')
    ass_cert = key2.sign(hash,K)
    f = open(pasta +'/cert_'+cred +'.cert','w')
    f.write("Credenciais:" +cred +'|' + "\n" + f"Public key:(n={hex(key.n)}, e={hex(key.e)})" + "\n" + "Credenciais assinante:" + credencial + '\n'+str(ass_cert))
    f.close()
    ##################### VERIFICANDO
    f = open(pasta +'/cert_'+cred +'.cert','r')
    linhas = f.readlines()
    tt = linhas[3].lstrip("(").strip(",)")
    teste = (linhas[0] + linhas[1] + linhas[2]).encode('utf-8')
    hash2 = int.from_bytes(sha512(teste).digest(), byteorder='big')
    f.close()
    if os.path.isfile('cert_'+credencial +'.cert') == False:
        print("CERTIFICADO NÃO VALIDADO COM SUCESSO, CERTIFICADO DO ASSINANTE NÃO EXISTE!!")
        cmd = 'rm cert_'+cred +'.cert'
        os.system(cmd)
        return
    f = open(pasta +'/cert_'+credencial +'.cert','r')
    linhas = f.readlines()
    ne = linhas[1].split('=')
    n = int(ne[1].strip(", e"),16)
    e = int(ne[2].strip(")\n"),16)
    newtuple = (int(tt),)
    pub_key = RSA.construct((n, e))
    hash_desc = pub_key.verify(hash2,newtuple)
    f.close()
    if hash_desc == True :
        print("CERTIFICADO VALIDADO COM SUCESSO!!")
    else:
        print("CERTIFICADO NÃO VALIDADO COM SUCESSO!!")
        cmd = 'rm cert_'+cred +'.cert'
        os.system(cmd)

def verifica_valido():
    caminhos = [os.path.join(pasta, nome) for nome in os.listdir(pasta)]
    arquivos = [arq for arq in caminhos if arq.lower().endswith(".txt")]
    if arquivos == []:
        print("Não existem documentos na pasta para verificar!!!")
        return
    print("Qual documento deseja verificar a assinatura?")
    print(arquivos)
    arqv = open(arquivos[int(input()) - 1],'r')
    linhas = arqv.readlines()
    if 'Assig{' not in linhas[len(linhas) - 1]:
        print("Arquivo não assinado")
        return
    count = 0
    conteudo = ''
    for lin in linhas:
        count = count + 1
        if count > (len(linhas)-3):
            break
        conteudo = conteudo + lin
    conteudo = conteudo[:-1]
    conteudo = conteudo.encode("utf-8")
    hash = int.from_bytes(sha512(conteudo).digest(), byteorder='big')
    assinatura = linhas[len(linhas)-1].lstrip("Assig{(").strip(",)}")
    newtuple = (int(assinatura),)
    arquivos = [arq for arq in caminhos if arq.lower().endswith(".cert")]
    if arquivos == []:
        print("Não existem certificados na pasta!!!")
        return
    for arq in arquivos:
        cert = open(arq,'r')
        cert_linhas = cert.readlines()
        ne = cert_linhas[1].split('=')
        n = int(ne[1].strip(", e"),16)
        e = int(ne[2].strip(")\n"),16)
        pub_key = RSA.construct((n, e))
        hash_desc = pub_key.verify(hash,newtuple)
        if hash_desc:
            print("Documento valido para o certificado: " + arq)
            return
    print("Assinatura inválida!!")

    
     
#adicionar mudança da userFriendlyRNG t = time.perf_counter() linha 77   
if __name__ == '__main__':
    func = int
    while(1):
        os.system('clear')
        print("--------MENU--------")
        print("1-GERAR CERTIFICADO")
        print("2-ASSINAR DOCUMENTO")
        print("3-VERIFICAR ASSINATURA")
        print("4-GERAR CERTIFICADO COM ASSINATURA DE OUTRO")
        print("5-QUIT")
        print("--------------------")
        func = int(input())
        os.system('clear')
        if func == 1:
            gerar_certificados()
        elif func == 2:
            assinar()
        elif func == 3:
            verifica_valido()
        elif func == 4:
            gerar_assinados()
        elif func == 5:
            break   
        else:
            os.system('clear')
            print("Comando inválido!!")
        time.sleep(5)    