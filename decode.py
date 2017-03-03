# coding=utf8

import ctypes
c_uint8 = ctypes.c_uint8

class HiFlags_bits(ctypes.BigEndianStructure):
    _fields_ = [
        ("bit7", c_uint8, 1),  # asByte & 1
        ("bit6", c_uint8, 1),  # asByte & 2
        ("bit5", c_uint8, 1),  # asByte & 4
        ("bit4", c_uint8, 1),  # asByte & 8
    ]

class HiFlags(ctypes.Union):
    _anonymous_ = ("bit",)
    _fields_ = [
        ("bit", HiFlags_bits),
        ("asByte", c_uint8)
    ]

class LowFlags_bits(ctypes.LittleEndianStructure):
    _fields_ = [
        ("bit0", c_uint8, 1),
        ("bit1", c_uint8, 1),
        ("bit2", c_uint8, 1),
        ("bit3", c_uint8, 1),
    ]

class LowFlags(ctypes.Union):
    _anonymous_ = ("bit",)
    _fields_ = [
        ("bit", LowFlags_bits),
        ("asByte", c_uint8)
    ]

def highfields (abyte):
    flags = HiFlags()
    flags.asByte = abyte
    return (flags.bit7, flags.bit6, flags.bit5, flags.bit4)

def lowfields (abyte):
    flags = LowFlags()
    flags.asByte = abyte
    return (flags.bit3, flags.bit2, flags.bit1, flags.bit0)

def bit2ascii (b3, b2, b1, b0):
    return (str(b3)+str(b2)+str(b1)+str(b0))

def calcula_sig(buf, seed=0xAAAA):
    for b in buf:
        b = ord(b)
        t = seed
        seed = (seed << 1) & 0x1FF
        if seed >= 0x100:
            seed += 1
        seed = ((((seed + (t >> 8) + b) & 0xFF) | (t << 8))) & 0xFFFF
    return seed

def carrega_pacotes(filename):
    log = open(filename, "ro")
    # carregando arquivo como lista de pacotes
    packets = log.read().split("\xbd")
    # removendo strings vazias da lista
    packets = list(filter(None, packets))
    # fazendo unquote
    packets = unquote_pacotes(packets)
    # removendo invalidos (nullifier)
    packets = remove_invalidos(packets)
    return packets

def unquote_pacotes(packets):
    # faz o unquote dos pacotes
    for c1 in range(len(packets) - 1):
        pb = packets[c1]
        # so precisa checar ate o penultimo byte
        for c2 in range(len(pb) - 1):
            # checando por "\xbc" e "\xdd"
            if pb[c2] == "\xbc" and pb[c2 + 1] == "\xdd":
                print ("realizando unquote no indice " + str(c2 + 1) + " do pacote " + str(c1 + 1) + "\n")
                # realizando a troca
                if c2 + 2 > len(pb) - 1:
                    temp = pb[0:c2] + "\xbd"
                else:
                    temp = pb[0:c2] + "\xbd" + pb[c2 + 2:]
                # substituindo o pacote
                packets[c1] = temp
            # checando por "\xbc" e "\xdc"
            if pb[c2] == "\xbc" and pb[c2 + 1] == "\xdc":
                print ("realizando unquote no indice " + str(c2 + 1) + " do pacote " + str(c1 + 1) + "\n")
                # realizando a troca
                if c2 + 2 > len(pb) - 1:
                    temp = pb[0:c2] + "\xbc"
                else:
                    temp = pb[0:c2] + "\xbc" + pb[c2 + 2:]
                # substituindo o pacote
                packets[c1] = temp
    return packets

def dec_sigcheck(pb):
    a = "Pacote inválido"
    #pacote é válido quando o resultado do nullifier é zero
    if calcula_sig(pb) == 0:
        a = "OK"
    return a

def checa_pacote(pb):
    sigcheck = dec_sigcheck(pb)
    returnval = False
    if sigcheck == "OK":
        tam = len(pb) - 2
        #checagem de tamanho maximo e minimo do pacote pakbus
        if tam >= 4 and tam <= 1008:
            returnval = True
    return returnval

def remove_invalidos(allpackets):
    returnval = []
    for pb in allpackets:
        if checa_pacote(pb):
            returnval.append(pb)
    return returnval

def dec_linkstate(pb):
    # decodifica linkstate
    s="Vazio"
    if highfields(ord(pb[0])) == (1, 0, 0, 0):
        s="Offline"
    if highfields(ord(pb[0])) == (1, 0, 0, 1):
        s="Ring"
    if highfields(ord(pb[0])) == (1, 0, 1, 0):
        s="Ready"
    if highfields(ord(pb[0])) == (1, 0, 1, 1):
        s="Finished"
    if highfields(ord(pb[0])) == (1, 1, 0, 0):
        s="Pause"
    return s

def dec_physaddr(pb):
    # decodifica Destination physical address
    a, b, c = "Vazio", "Vazio", "Vazio"
    # pega os quatro primeiro bits
    b3, b2, b1, b0 = lowfields(ord(pb[0]))
    a = bit2ascii(b3, b2, b1, b0)
    # pega os proximos quatro bits
    b3, b2, b1, b0 = highfields(ord(pb[1]))
    b = bit2ascii(b3, b2, b1, b0)
    # pega os ultimos quatro bits
    b3, b2, b1, b0 = lowfields(ord(pb[1]))
    c = bit2ascii(b3, b2, b1, b0)
    return (a + b + c, int(a + b + c, 2))

def dec_srcphysaddr(pb):
    # decodifica Source physical address
    a, b, c = "Vazio", "Vazio", "Vazio"
    # pega os quatro primeiro bits
    b3, b2, b1, b0 = lowfields(ord(pb[2]))
    a = bit2ascii(b3, b2, b1, b0)
    # pega os proximos quatro bits
    b3, b2, b1, b0 = highfields(ord(pb[3]))
    b = bit2ascii(b3, b2, b1, b0)
    # pega os ultimos quatro bits
    b3, b2, b1, b0 = lowfields(ord(pb[3]))
    c = bit2ascii(b3, b2, b1, b0)
    return (a + b + c, int(a + b + c, 2))

def dec_expmorecod(pb):
    # decodifica expect more codes.
    a="Vazio"
    if highfields(ord(pb[2]))[:2] == (0, 0):
        a="This is the last message to this destination from this source."
    if highfields(ord(pb[2]))[:2] == (0, 1):
        a="Expect more messages to this destination from the same source."
    if highfields(ord(pb[2]))[:2] == (1, 0):
        a="Neutral message that has no impact on whether to expect more."
    if highfields(ord(pb[2]))[:2] == (1, 1):
        a="Expect more messages in the reverse direction."
    return a

def dec_priority(pb):
    # decodifica priority.
    a = "Vazio"
    if highfields(ord(pb[2]))[2:] == (0, 0):
        a="Highest priority."
    if highfields(ord(pb[2]))[2:] == (0, 1):
        a="Normal priority."
    if highfields(ord(pb[2]))[2:] == (1, 0):
        a="Low priority."
    if highfields(ord(pb[2]))[2:] == (1, 1):
        a="Lowest priority."
    return a

def dec_hiproto(pb):
    a = "Vazio"
    # decodifica hiproto.
    if highfields(ord(pb[4])) == (0, 0, 0, 0):
        a = "Pakctrl message."
    elif highfields(ord(pb[4])) == (0, 0, 0, 1):
        a = "BMP5 message."
    elif len(pb) == 6 and a == "Vazio":
        a = "SerPkt message."
    else:
        a = "Undocumented." + str(highfields(ord(pb[4])))
    return a

def dec_destnodeid(pb):
    # decodifica Destination node id
    a, b, c = "Vazio", "Vazio", "Vazio"
    # pega os quatro primeiro bits
    b3, b2, b1, b0 = lowfields(ord(pb[4]))
    a = bit2ascii(b3, b2, b1, b0)
    # pega os proximos quatro bits
    b3, b2, b1, b0 = highfields(ord(pb[5]))
    b = bit2ascii(b3, b2, b1, b0)
    # pega os ultimos quatro bits
    b3, b2, b1, b0 = lowfields(ord(pb[5]))
    c = bit2ascii(b3, b2, b1, b0)
    return (a + b + c, int(a + b + c, 2))

def dec_hopcount(pb):
    # decodifica hopcount
    a = "Vazio"
    hop = str(int(''.join(map(str, highfields(ord(pb[6])))), 2))
    if hop == 0:
        a = "Direct connected (hopcount = 0)"
    else:
        a = hop
    return a

def dec_srcnodeid(pb):
    # decodifica Source node id
    a, b, c = "Vazio", "Vazio", "Vazio"
    # pega os quatro primeiro bits
    b3, b2, b1, b0 = lowfields(ord(pb[6]))
    a = bit2ascii(b3, b2, b1, b0)
    # pega os proximos quatro bits
    b3, b2, b1, b0 = highfields(ord(pb[7]))
    b = bit2ascii(b3, b2, b1, b0)
    # pega os ultimos quatro bits
    b3, b2, b1, b0 = lowfields(ord(pb[7]))
    c = bit2ascii(b3, b2, b1, b0)
    return (a + b + c, int(a + b + c, 2))

def dec_collectfields(fl):
    if ord(fl[0]) == 0 and ord(fl[1]) == 0:
        s = " | Field number - all fields | "
    else:
        s = " | Field number - " + fl[:-2] + " |"
    return s

def dec_collectmode(pl):
    r = "Nenhum"
    s = dec_collectfields(pl[13:])
    a = pl[4]
    if hex(ord(a)) == hex(0x3):
        r = "Collect data from oldest record to newest in each table."
    if hex(ord(a)) == hex(0x4):
        r = "Collect data from P1 to newest record, or from the oldest if P1 does not exist."
    if hex(ord(a)) == hex(0x5):
        r = "Collect the most recent records where P1 desiginates how many records to collect."
    if hex(ord(a)) == hex(0x6):
        r = "Collect records betwen (including) P1 and (excluding) P2."
        s = " | P2 - " +  str(ord(pl[13]))  + str(ord(pl[14])) + str(ord(pl[15])) + str(ord(pl[16])) + dec_collectfields(pl[17:])
    if hex(ord(a)) == hex(0x7):
        r = "Collect records betwen (including) P1 and (excluding) P2 in times relative to Jan 1, 1990."
    if hex(ord(a)) == hex(0x8):
        r = "Collect a partial record when the record size exceeded maximum packet size. P1 specifies record number and P2 specifies byte offset into the record partial data."
    return r, s

def dec_responsecode(pl):
    r = "Nenhum"
    a = pl[2]
    if hex(ord(a)) == hex(0x0):
        r = "Completed"
    if hex(ord(a)) == hex(0x1):
        r = "Permission denied"
    if hex(ord(a)) == hex(0x2):
        r = "Insufficient resources"
    if hex(ord(a)) == hex(0x7):
        r = "Invalid table definition"
    return r


def dec_func(payload,hiproto):
    #decodifica codigo da funcao do protocolo de alto nivel
    a = hex(ord((payload[0])))
    b = "no"
    c = str(hex(ord(payload[1])))
    s1 = "Desconhecido (" + a + ")"
    s2 = "| Transaction (?) - " + c + " |"

    if a == hex(0x9) and hiproto == "Pakctrl message.":
        if hex(ord(payload[2])) == hex(0x1):
            b = "yes"
        s1 = "Hello command msg"
        s2 = "| Transaction - " + c + " | Router - " + b + " | Hop metric - " + hex(ord(payload[3])) + " | Link verification interval - " + str(ord(payload[4])) + " " + str(ord(payload[5])) + " |"

    if a == hex(0x87) and hiproto == "Pakctrl message.":
        s1 = "Get Settings Response msg"
        s2 = "| Transaction - " + c + " | Settings - " + payload[2:] + " |"

    if a == hex(0x89) and hiproto == "Pakctrl message.":
        if hex(ord(payload[2])) == hex(0x1):
            b = "yes"
        s1 = "Hello response msg"
        s2 = "| Transaction - " + c + " | Router - " + b + " | Hop metric (copied) - " + hex(ord(payload[3])) + " | Link verification interval / 2.5 - " + str(ord(payload[4])) + " " + str(ord(payload[5])) + " |"

    if a == hex(0x9) and hiproto == "BMP5 message.":
        cm, sf  = dec_collectmode(payload)
        s1 = "Collect data command body"
        s2 = "| Transaction - " + c + " | Security code - " + str(ord(payload[2])) + " " + str(ord(payload[3])) + " | Collect mode - " + cm + " | Table nbr - " + str(ord(payload[5])) + str(ord(payload[6])) + " | Table def sig - " + str(hex(ord(payload[7]))) + " " + str(hex(ord(payload[8]))) + " | P1 - " +  str(ord(payload[9]))  + str(ord(payload[10])) + str(ord(payload[11])) + str(ord(payload[12])) + sf

    if a == hex(0x89) and hiproto == "BMP5 message.":
        s1 = "Collect data response body"
        s2 = "| Transaction - " + c + " | Response code - " + dec_responsecode(payload) + " | Table nbr - " + str(ord(payload[3])) + str(ord(payload[4])) + " | BegRegNbr - " + str(ord(payload[5]))  + str(ord(payload[6])) + str(ord(payload[7])) + str(ord(payload[8])) + " | payload - " + payload[9:]

    if a == hex(0xa1) and hiproto == "BMP5 message.":
        s1 = "Please Wait msg"
        s2 = "| Transaction (same as waiting msg) - " + c + " | Msgtype - " + str(hex(ord(payload[2]))) + " | Time to wait (30s max) - " + str(ord(payload[3])) + str(ord(payload[4])) + " |"

    #undocumented

    if a == hex(0x7) and hiproto == "Pakctrl message.":
        s1 = "Undocumented 0x7 (get settings command msg?)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    if a == hex(0xe) and hiproto == "Pakctrl message.":
        s1 = "Undocumented 0xe pakctrl (reset? transact is zero always?)"
        s2 = "| Transaction - " + c + " | Payload - "
        if len(payload[2:]) == 0:
            s2 = s2 + "no payload |"
        else:
            for p in payload[2:]:
                print hex(p)
                s2 = s2 + str(ord(p)) + " "
            s2 = s2 + " |"

    if a == hex(0x3) and hiproto == "BMP5 message.":
        s1 = "Undocumented 0x3 (collect data cmd?)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    if a == hex(0x4) and hiproto == "BMP5 message.":
        s1 = "Undocumented 0x4 (program send?)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    if a == hex(0xb) and hiproto == "BMP5 message.":
        s1 = "Undocumented 0xb ?? (transact 0x8e)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    if a == hex(0xe) and hiproto == "BMP5 message.":
        s1 = "Undocumented 0xe (table fields cmd?)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    if a == hex(0x83) and hiproto == "BMP5 message.":
        s1 = "Undocumented 0x83 (collect data response?)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    if a == hex(0x84) and hiproto == "BMP5 message.":
        s1 = "Undocumented 0x84 (program download response?)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    if a == hex(0x8b) and hiproto == "BMP5 message.":
        s1 = "Undocumented 0x8b ?? (transact 0x8e)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    if a == hex(0x8e) and hiproto == "BMP5 message.":
        s1 = "Undocumented 0x8e (table fields response?)"
        s2 = "| Transaction - " + c + " | Payload - " + payload[2:] + " |"

    return (s1, s2)

def showpkts(allpackets, output):

    # mostra os pacotes

    showpkt = False
    c1 = 1

    output.write(" -= Resumo =-\n")
    output.write("Quatidade de pacotes : " + str(len(allpackets)) + "\n")
    for key in allpackets:
        dir = allpackets[key][0]
        if dir:
            dir="Entrada"
        else:
            dir="Saida"
        pb = allpackets[key][1]
        #depois que já foi checado que o pacote esta OK removemos o ultimos dois bytes (nullifier)
        pb = pb[:-2]
        # payload
        payload = pb[8:]

        trans = "Nenhum"
        cod = "Nenhum"
        hi = "Nenhum"
        ls = "Nenhum"
        if len(pb) > 0:
            ls = dec_linkstate(pb)
        if len(pb) > 4:
            hi = dec_hiproto(pb)
        if len(pb) > 8:
            cod, s = dec_func(payload, hi)
            trans = hex(ord(pb[9]))
        output.write(str(c1) + " | dir : " + dir + " | tamanho : " + str(len(pb)) + " | hi-proto : " + hi + " | link : " + ls + " | cod. funcao : " + str(cod) + " | transact : " + str(trans) + " \n")
        c1 += 1
    output.write("\n")
    c1 = 1

    for key in allpackets:
        dir = allpackets[key][0]
        if dir:
            dir="Entrada"
        else:
            dir="Saida"
        pb = allpackets[key][1]
        output.write("\n")
        output.write(" -= Informacoes gerais =-\n")
        output.write("Direcao : " + dir + "\n")
        output.write("Numero do pacote : " + str(c1) + "\n")
        c1 += 1
        output.write("Numero do pacote no stream original : " + str(allpackets[key][2] + 1) + "\n")

        output.write("Tamanho do pacote completo : " + str(len(pb)) + " bytes.\n")

        output.write("Nullfier : ")
        output.write("| ")
        for b in pb[-2:]:
            output.write(hex(ord(b)) + " | ")
        output.write("\n")

        #checagem ja foi feita no momento da carga dos pacotes
        output.write("Signature check : OK\n")

        #depois que já foi checado que o pacote esta OK removemos o ultimos dois bytes (nullifier)
        pb = pb[:-2]
        #payload
        payload = pb[8:]

        output.write("Tamanho do pacote pakbus : " + str(len(pb)) + " bytes.\n")
        if showpkt:
            output.write("Pacote pakbus : ")
            c2 = 0
            output.write("| ")
            for b in pb:
                c2 += 1
                output.write(str(c2) + " - " + str(hex(ord(b))) + " | ")
            output.write("\n")

        # decodifica cabecalho
        output.write(" -= Dados do cabecalho =-\n")

        if len(pb) > 0:
            output.write("linkstate - ")
            output.write(dec_linkstate(pb) + "\n")
            output.write("Destination physical address - ")
            output.write(str(dec_physaddr(pb)[1]) + "\n")

        if len(pb) > 2:
            output.write("expect more codes - ")
            output.write(dec_expmorecod(pb) + "\n")

            output.write("priority - ")
            output.write(dec_priority(pb) + "\n")

            output.write("Source physical address - ")
            output.write(str(dec_srcphysaddr(pb)[1]) + "\n")

        if len(pb) > 4:
            output.write(" -= Dados do protocolo de alto nivel =-\n")
            hiproto = dec_hiproto(pb)
            output.write("hiproto - ")
            output.write(hiproto + "\n")

            output.write("Destination node id - ")
            output.write(str(dec_destnodeid(pb)[1]) + "\n")

            output.write("hopcount - ")
            output.write(dec_hopcount(pb) + "\n")

            output.write("Source node id - ")
            output.write(str(dec_srcnodeid(pb)[1]) + "\n")

        # decodifica corpo da msg
        # decodifica codigo
        if len(pb) > 8:
            cod, func = dec_func(payload, hiproto)
            output.write(" -= Dados do corpo da mensagem =-\n")
            output.write("Tamanho do payload : " + str(len(payload)) + "\n")
            if func[:14] == "| Desconhecido" :
                output.write("Descricao - " + str(cod) + "\n")
                output.write("Mensagem (payload): ")
                output.write("| ")
                for b in payload:
                    output.write(hex(ord(b)) + " | ")
                output.write("\n")
            else:
                output.write("| Descricao : " + cod + " " + func + "\n")
    return

def createfile(filename):
    output = open(filename, "w")
    return output

#corpo principal
if __name__ == '__main__':
    filename_in = "input.txt"
    filename_out = "output.txt"

    # datalogger pakbus address
    dl_addr = 1

    # Device configurator
    pc_addr = 4089
    # PC200W
    #pc_addr = 4092

    filename_debug = "../../../../pbdecode_in.txt"
    filename_debug2 = "../../../../pbdecode_out.txt"
    filename_debug3 = "../../../../pbdecode.txt"

    output = createfile(filename_debug)
    output2 = createfile(filename_debug2)
    output3 = createfile(filename_debug3)

    allpackets_in = carrega_pacotes(filename_in)
    allpackets_out = carrega_pacotes(filename_out)

    #debug carrega todos os pacotes (indepedente do endereco)
    debug = False

    #cria dicionarios e carrega dado como lista [ Direcao, pb, id_original ]
    allpackdic_in = {}
    allpackdic_out = {}
    k = 0
    c = 0
    for pb in allpackets_in:
        # filtra o trafego especifico
        if (dec_srcphysaddr(pb)[1] == dl_addr and dec_physaddr(pb)[1] == pc_addr) or debug:
            allpackdic_in[k] = [True, pb, c]
            k+=1
        c+=1
    k = 0
    c = 0
    for pb in allpackets_out:
        # filtra o trafego especifico
        if (dec_srcphysaddr(pb)[1] == pc_addr and dec_physaddr(pb)[1] == dl_addr) or debug:
            allpackdic_out[k] = [False, pb, c]
            k+=1
        c+=1

    #mistura dos pacotes
    #metodo padrao out + in

    allpackdic = {}

    c = 0
    for key in allpackdic_out:
        allpackdic[c] = allpackdic_out[key]
        c += 1
    for key in allpackdic_in:
        allpackdic[c] = allpackdic_in[key]
        c += 1

    print ("Capiturados " + str(len(allpackdic_in)) + " pacotes pakbus (in)...\n")
    print ("Capiturados " + str(len(allpackdic_out)) + " pacotes pakbus (out)...\n")

    print ("Tudo pronto!\n")

    showpkts(allpackdic_in, output)
    showpkts(allpackdic_out, output2)
    showpkts(allpackdic, output3 )

    print ("Finalizando...\n")

    output.close()
    output2.close()
    output3.close()