# Proyecto_ciberseguridad

Este proyecto tiene como objetivo el desarrollo de un software que implemente las características de criptografía vistas en el curso de ciberseguridad. En específico se solucionará el siguiente Enunciado:

***Transferencia segura de archivos con esquema de clave simétrica:** Deben desarrollarse dos programas, uno cliente y uno servidor. El programa servidor debe escuchar por un puerto determinado, y esperar la conexión del cliente. El cliente recibe un nombre de archivo como parámetro. Una vez conectados cliente y servidor, el cliente debe negociar una clave de cifrado con el servidor empleando el algoritmo Diffie-Hellman (convencional o de curvas elípticas), y luego transferir el archivo empleando el algoritmo AES con clave de 256 bits, usando la clave previamente negociada. Al final del proceso el cliente debe calcular el hash SHA-256 del archivo que acaba de transmitir, y enviarlo al servidor. El servidor debe calcular el hash sobre el archivo recibido, y compararlo con el hash recibido del cliente. Si son iguales, debe indicarse que el archivo se transfirió adecuadamente.*

## Tecnología empleada
![Go Version](https://img.shields.io/badge/Go-1.25-blue.svg?logo=go)

Para la resolución de este proyecto emplee el lenguaje de programación **GO** Ya que me es más cómodo y tiene una librería de criptografía bastante potente y segura, además de un manejo muy versátil de los protocolos de red, rapidez de ejecución y muy buen manejo de conexiones múltiples.

Hablando específicamente de las soluciones para el componente criptográfico se escogieron las siguientes tecnologías:
* **Diffie-Hellman de curvas elípticas (ECDH):** Este se emplea ya que es un algoritmo que permite tener mejor manejo de recursos ya que no usa números primos grandes y también está el componente del reto personal de emplearlo ya que anteriormente no lo he usado.
* **AES-256 GCM:**  En vez de Usar AES-256 en su forma base, decidí agregarle una capa mas de seguridad y emplear también GCM que agrega autenticación.

## Metodologia
Al ser una aplicación que funciona bajo el modelo de _cliente - Servidor_ se determino la necesidad de 3 componentes:
1. **Cliente:** Encargado de tomar el archivo, calcular el hash inicial, encriptar el archivo y enviarlo al servidor.
2. **Servidor:** Encargado de recibir el archivo, desencriptarlo y validar el hash.
3. **Componente de formato para las transferencias:** Se encarga de dar un formato común (entre el cliente y servidor) tanto a la negociación de clave como al envió y recepción del archivo.

Adicionalmente se identifica la necesidad de abstraer en el código los siguientes componentes necesarios para solucionar el enunciado:
* Negociación de clave a través de Diffie-Hellman de curvas elípticas (ECDH).
* Uso de la clave negociada para encriptar y desencriptar archivos con AES-256 GCM.
* Calculo y envió del hash SHA-256 por parte del cliente.
* Recepción y validación del hash SHA-256 por parte del servidor (también el envió del resultado al cliente).

## Dificultades en el desarrollo

A lo largo del desarrollo se identificaron las siguientes dificultades:
* **Conceptualización y abstracción del ECDH:** Fue complejo para mi entender el funcionamiento del algoritmo para la negociación de la clave y principalmente el cómo abstraerlo a Go empleando las librerías de para la creación de curvas, matemáticas y criptografía.
* **identificación de los formatos y tipos de datos a usar:** En la abstracción de la mayoría de las funcionalidades fue un reto identificar el tipo de dato que era necesario y el formato que se debía utilizar para cada caso.
* **conceptualización de la integración entre ECDH y AES_256:** Fue complejo entender como integrar la clave negociada con ECDH para usarla en la encriptación y desencriptación AES-256.

## Conclusiones del proyecto
Este proyecto fue un reto bastante agradable ya que tuve un acercamiento bastante cercano al uso de estas herramientas de criptografía directamente en el código. Con esto reconociendo el valor del uso de tecnologías más robustas para el desarrollo de comunicaciones más seguras y de todas las facilidades que hay hoy en día para poder usar estas herramientas criptográficas en pro de tener aplicaciones cada vez más seguras.


## Uso del aplicativo
*Antes de usar el cliente o el servidor debe tener instalado Go 1.25 en su máquina.*

1. Primero debe estar en una consola de línea de comando y ubicado en la carpeta raíz del proyecto y ejecutar el servidor (cerciórese de que el puerto 8080 de su máquina no está en uso):
```bash
go run .\cmd\server\main.go
```
2.Ahora cree un archivo de texto en la raíz del proyecto y escriba contenido en él. Este archivo se usará para probar que el aplicativo funcione.
3. Por último corra el cliente de la siguiente forma:
```bash
 go run .\cmd\client\main.go --archivo my_file.txt
```
 4. Si todo salió bien debería de en la raíz del proyecto encontrar un archivo con un nombre similar a este ```RECEIVED_my_file.txt```.
