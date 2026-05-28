import os
import re
import email
import shutil
from email import policy
from email.parser import BytesParser


# Palabras que suelen aparecer en phishing con un peso de riesgo, cuanto más alto el número, más sospechosa es la palabra
PALABRAS_SPAM = {
    # Urgencia
    "urgente": 40, "urgentemente": 40, "inmediatamente": 35,
    "actúa ahora": 50, "actua ahora": 50, "última oportunidad": 45,
    "expira hoy": 50, "caduca hoy": 50, "tiempo limitado": 35,
    # Premios y dinero
    "premio": 50, "ganador": 50, "has ganado": 60, "lotería": 55,
    "millones": 40, "dinero gratis": 65, "transferencia": 35,
    "herencia": 55, "inversión garantizada": 60,
    # Phishing de credenciales
    "contraseña": 45, "password": 45, "usuario": 30,
    "verifica tu cuenta": 60, "confirma tu cuenta": 60,
    "acceso suspendido": 55, "cuenta bloqueada": 55,
    "datos bancarios": 65, "tarjeta de crédito": 50,
    "número de cuenta": 55, "pin": 40, "cvv": 65,
    # Links sospechosos
    "haz clic aquí": 45, "haz click aqui": 45, "enlace seguro": 30,
    "descarga ahora": 40, "instala ahora": 45, "actualiza ahora": 40,
    # Spam comercial típico
    "oferta exclusiva": 30, "gratis": 25, "sin coste": 25,
    "100% gratis": 40, "descuento especial": 20,
    # Palabras en inglés que también aparecen
    "free": 20, "winner": 50, "click here": 45, "verify account": 60,
    "suspended": 45, "confirm password": 65, "bank account": 50,
    "credit card": 45, "limited time": 35, "act now": 50,
}

# Dominios reales que suelen imitar los atacantes
DOMINIOS_LEGITIMOS = [
    "google.com", "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "microsoft.com", "apple.com", "icloud.com", "amazon.com", "paypal.com",
    "ebay.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "bankinter.com", "caixabank.com", "santander.com", "bbva.com", "ing.com",
    "correos.es", "hacienda.gob.es", "seg-social.es", "agenciatributaria.es",
]

# Acortadores de URL y correos temporales, nadie legítimo los usa
DOMINIOS_MALOS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "mailinator.com", "tempmail.com", "guerrillamail.com",
]

# La distancia de levenshtein mesura quanto de diferentes son dos palabrass calculando cuántas operaciones como insertar, borrar, sustituir..., hacen falta para pasar de s1 a s2
def distancia_levenshtein(s1, s2):
    m = len(s1)
    n = len(s2)
    # creamos una matriz de m+1 filas y n+1 columnas
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    # rellenamos la primera fila y columna
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                # cogemos el mínimo de borrar, insertar o sustituir
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])

    return dp[m][n]

# comprueba si un dominio es una imitación falsa de uno legítimo
def es_typosquatting(dominio):
    # si la distancia es <= 2 significa que solo hay 1 o 2 caracteres de diferencia, sospechoso
    dominio = dominio.lower().strip()
    for legitimo in DOMINIOS_LEGITIMOS:
        if dominio == legitimo:
            return False  # es el mismo no pasa nada
        if distancia_levenshtein(dominio, legitimo) <= 2:
            return True
    return False


def extraer_dominios(texto):
    # busca dominios en URLs y también en direcciones de email
    patron = r'https?://([a-zA-Z0-9.\-]+)'
    dominios = re.findall(patron, texto)
    patron_email = r'@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})'
    dominios += re.findall(patron_email, texto)
    return dominios

class ArbolBST:
    # Árbol BST para guardar las palabras sospechosas
    #Usaamos _ en los métodos internos para indicar que son privados

    def __init__(self):
        self.raiz = None

    def insertar(self, palabra, peso):
        self.raiz = self._insertar(self.raiz, palabra.lower(), peso)

    def _insertar(self, nodo, palabra, peso):
        # caso base: posición vacía, creamos el nodo aquí
        if nodo is None:
            return NodoBST(palabra, peso)
        if palabra < nodo.palabra:
            nodo.izquierdo = self._insertar(nodo.izquierdo, palabra, peso)
        elif palabra > nodo.palabra:
            nodo.derecho = self._insertar(nodo.derecho, palabra, peso)
        else:
            # ya estaba en el árbol, solo sumamos una aparición más
            nodo.frecuencia += 1
        return nodo

    def buscar(self, palabra):
        return self._buscar(self.raiz, palabra.lower())

    def _buscar(self, nodo, palabra):
        if nodo is None or nodo.palabra == palabra:
            return nodo
        if palabra < nodo.palabra:
            return self._buscar(nodo.izquierdo, palabra)
        return self._buscar(nodo.derecho, palabra)

    def calcular_riesgo_total(self):
        return self._calcular_riesgo(self.raiz)

    def _calcular_riesgo(self, nodo):
        if nodo is None:
            return 0
        izq = self._calcular_riesgo(nodo.izquierdo)
        actual = nodo.peso * nodo.frecuencia
        der = self._calcular_riesgo(nodo.derecho)
        return izq + actual + der

    def palabras_encontradas(self):
        resultado = []
        self._listar(self.raiz, resultado)
        return resultado

    def _listar(self, nodo, lista):
        if nodo is None:
            return
        self._listar(nodo.izquierdo, lista)
        lista.append((nodo.palabra, nodo.peso, nodo.frecuencia))
        self._listar(nodo.derecho, lista)

# Clase base para todos los filtros
class FiltroCorreo:
    # Cada filtro recibe el contenido del correo y devuelve una puntuación de riesgo
    def analizar(self, asunto, remitente, cuerpo):
        pass

# Busca palabras sospechosas en el correo usando el árbol BST
class FiltroPorPalabrasClave(FiltroCorreo):

    def __init__(self):
        # cargamos las palabras sospechosas en el árbol al crear el filtro
        self.arbol = ArbolBST()
        for palabra, peso in PALABRAS_SPAM.items():
            self.arbol.insertar(palabra, peso)

    def analizar(self, asunto, remitente, cuerpo):
        texto = (asunto + " " + cuerpo).lower()
        arbol_encontradas = ArbolBST()
        razones = []

        for palabra, peso in PALABRAS_SPAM.items():
            if palabra in texto:
                arbol_encontradas.insertar(palabra, peso)

        puntuacion = arbol_encontradas.calcular_riesgo_total()

        for palabra, peso, freq in arbol_encontradas.palabras_encontradas():
            razones.append(f"Palabra sospechosa: '{palabra}' (peso {peso}, aparece {freq}x)")

        return puntuacion, razones

class FiltroPorRemitenteSospechoso(FiltroCorreo): # Mira los dominios del remitente y del cuerpo del correo

    def analizar(self, asunto, remitente, cuerpo):
        puntuacion = 0
        razones = []
        texto_completo = remitente + " " + cuerpo

        dominios = extraer_dominios(texto_completo)

        for dominio in dominios:
            dominio_limpio = dominio.lower().strip()

            if dominio_limpio in DOMINIOS_MALOS:
                puntuacion += 60
                razones.append(f"Dominio en lista negra: {dominio_limpio}")

            elif es_typosquatting(dominio_limpio):
                puntuacion += 70
                razones.append(f"Posible typosquatting: {dominio_limpio}")

        if re.search(r'https?://[^/]*@', texto_completo):
            puntuacion += 50
            razones.append("URL sospechosa con @")

        return puntuacion, razones

class AnalizadorCorreo:
    # Aqui lo que nharemos es juntar todos los filtros y analiza cada correo .eml

    def init(self):
        self.filtros = [
            FiltroPorPalabrasClave(),
            FiltroPorRemitenteSospechoso(),
        ]

    def analizar_eml(self, ruta_archivo):
        # lee un archivo .eml y lo analiza con todos los filtros
        try:
            with open(ruta_archivo, "rb") as f:
                msg = BytesParser(policy=policy.default).parse(f)
        except Exception as e:
            return {"archivo": ruta_archivo, "error": str(e)}

        asunto = msg.get("Subject", "(sin asunto)")
        remitente = msg.get("From", "(desconocido)")

        # extraemos el texto del cuerpo
        cuerpo = ""
        if msg.is_multipart():
            for parte in msg.walk():
                if parte.get_content_type() == "text/plain":
                    try:
                        cuerpo += parte.get_content()
                    except:
                        pass
        else:
            try:
                cuerpo = msg.get_content()
            except:
                cuerpo = ""

        # aplicamos cada filtro y sumamos puntuaciones
        puntuacion_total = 0
        razones_total = []
        for filtro in self.filtros:
            puntuacion, razones = filtro.analizar(asunto, remitente, cuerpo)
            puntuacion_total += puntuacion
            razones_total += razones

        # clasificamos según la puntuación total
        if puntuacion_total >= 150:
            nivel = "PELIGROSO"
        elif puntuacion_total >= 60:
            nivel = "SOSPECHOSO"
        else:
            nivel = "SEGURO"

        return {
            "archivo": ruta_archivo,
            "asunto": asunto,
            "remitente": remitente,
            "puntuacion": puntuacion_total,
            "nivel": nivel,
            "razones": razones_total,
        }
    
def escanear_carpeta(carpeta, analizador):
    # Aqui recorre una carpeta y todas sus subcarpetas buscando archivos .eml
    resultados = []

    try:
        entradas = os.listdir(carpeta)
    except Exception as e:
        print(f"No se puede leer la carpeta {carpeta}: {e}")
        return resultados

    for entrada in entradas:
        ruta_completa = os.path.join(carpeta, entrada)

        if os.path.isdir(ruta_completa):
            # es una subcarpeta -> llamada recursiva
            resultados += escanear_carpeta(ruta_completa, analizador)

        elif os.path.isfile(ruta_completa) and entrada.lower().endswith(".eml"):
            # es un correo .eml -> analizarlo
            resultado = analizador.analizar_eml(ruta_completa)
            resultados.append(resultado)

    return resultados

def imprimir_reporte(resultados):
    # muestra un resumen de todos los correos analizados
    total = len(resultados)
    seguros = sum(1 for r in resultados if r.get("nivel") == "SEGURO")
    sospechosos = sum(1 for r in resultados if r.get("nivel") == "SOSPECHOSO")
    peligrosos = sum(1 for r in resultados if r.get("nivel") == "PELIGROSO")
    errores = sum(1 for r in resultados if "error" in r)

    print("\nREPORTE - CLASIFICADOR SPAM/PHISHING")
    print(f" Total analizados : {total}")
    print(f" Seguros          : {seguros}")
    print(f" Sospechosos      : {sospechosos}")
    print(f" Peligrosos       : {peligrosos}")
    print(f" Errores          : {errores}")

    for r in resultados:
        if "error" in r:
            print(f"\n[ERROR] {r['archivo']}: {r['error']}")
            continue

        nivel = r["nivel"]
        if nivel == "SEGURO":
            icono = "OK"
        elif nivel == "SOSPECHOSO":
            icono = "!!"
        else:
            icono = "XX"

        print(f"\n[{icono}] {nivel} (puntuacion: {r['puntuacion']})")
        print(f" Archivo   : {os.path.basename(r['archivo'])}")
        print(f" Asunto    : {r['asunto'][:70]}")
        print(f" Remitente : {r['remitente'][:70]}")

        if r["razones"]:
            print(" Razones:")
            for razon in r["razones"]:
                print(f" - {razon}")