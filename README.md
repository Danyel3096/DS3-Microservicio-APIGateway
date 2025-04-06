# Microservicio API Gateway

Microservicio API Gateway para distribuir las solicitudes entre microservicios.

## Requisitos previos

Antes de ejecutar el microservicio, asegúrate de tener instalado:

- Java 17 o superior
- Maven 3.8+

## Construcción del proyecto

Para compilar el proyecto, ejecuta:

```sh
mvn clean install
```

## Ejecución del microservicio

Para iniciar el microservicio, usa el siguiente comando:

```sh
mvn spring-boot:run
```

## Ejecución de pruebas

Para ejecutar las pruebas del proyecto, usa el siguiente comando:

```sh
mvn test
```

## Generación de JAR ejecutable

Si deseas generar un JAR ejecutable, usa:

```sh
mvn package
```

Luego, puedes ejecutar el JAR con:

```sh
java -jar target/gateway-service-0.0.1-SNAPSHOT.jar
```