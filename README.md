## Общий подход к созданию тестов

1. Старайтесь минимизировать кодовую базу теста и параметры компиляции теста таким образом, чтобы:
  - минимизировать время компиляции теста
  - устранить из параметров компиляции теста все ключи компилятора, в необходимости которых вы сомневаетесь (некоторые ключи могут оказывать неявное влияние на компиляцию, устраняющее ту проблему, которую вы заложили в исходный текст теста)
2. В случае, если вы не уверены в том, что интересующий вас участок кода действительно попадает в финальную компиляцию (например вы подозреваете, что компилятор может его соптимировать или удалить полностью), рекомендуется встроить в исходный текст теста в непосредственной близости к интересующему участку гарантированно обнаруживаемую svace проблему. В частности таковой может выступать деление на ноль.
3. В исходном коде теста не должно быть каких-либо ошибок, выявляемых svace, за исключением той конкретной ошибки, которую вы закладываете в данный тест.
4. В целях обеспечения сборки в окружении, отличном от созданного на вашем хоста, рекомендуется оформлять тест в формате контейнера, для чего следует
подготовить минимизированный по числу дополнительно устанавливаемых пакетов докер-образ (файл Dockerfile, описывающий процесс создания образа командой `docker build`), основывающийся на ОС Ubuntu 22.04 и выполнять сборку и дальнейший анализ теста с помощью svace в данном образе.
4. Все найденные сущности (пакеты, классы и методы; их слабые параметры; описание известных уязвимостей; переиспользованные примеры кода и т.п.) рекомендуется приводить с ссылками на источники их исходного расположения в Интернет.

## Пример создания теста для исходного текста на ЯП C#

### Поиск кода, некорректное конфигурирование которого может привести к уязвимости создаваемого ПО - пониженной криптографической стойкости сетевого взаимодействия с ПО

В ходе анализа типовых классов и методов инфраструктуры dotnet **(версия .NET6)** был выявлен класс [SslStream](https://learn.microsoft.com/ru-ru/dotnet/api/system.net.security.sslstream?view=net-7.0), отвечающий за предоставление стандартного SSL/TLS-транспорта. Данный класс используется при создании и SSL-клиентов, и SSL-серверов. Данный класс содержит семейства методов, связанных с запуском сервера/клиента (например метод AuthenticateAsServer), одним из параметров которого может выступать конкретная версия (версии) SSL/TLS-протокола, в частности устаревшая и подверженная уязвимостям версия (версии) (SslProtocols.Ssl2, SslProtocols.Ssl3 и т.п.).

### Подготовка и запуск контейнера для сборки и анализа кода

Пример докер-файла:

```Dockerfile
FROM ubuntu:22.04

#Set Timezone or get hang during the docker build...
ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt update
RUN apt install -y vim dotnet6 dotnet-runtime-6.0
WORKDIR svace
RUN dotnet new console
```

Пример команд сборки образа и запуска контейнера (с доступностью сети хоста для взаимодействия с сервером лицензий svace):

```bash
dotnet build -t csharp_svace_test0 -f Dockerfile .
dotnet run --network=host --rm -it -v /opt/svace:/svace csharp_svace_test0 /bin/bash
```

### Подготовка кода теста

**Сперва стоит поискать какой-то готовый тестовый код, который использует интересующий нас класс, и изменить его, а не писать логику с нуля!**

Открыть и отредактировать созданный командой `dotnet new console` тестовый файл `Program.cs`. Удалить всё его содержимое. Вставить вместо него следующий код, содержащий запуск SSL-сервера в режиме взаимодействия по устаревшему и небезопасному протоколу SSL3. В данном примере анализируется перегрузка функции AuthenticateAsServer, принимающая на вход ровно одно значение версии протокола:

```C#
using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace Examples.System.Net
{
    public sealed class SslTcpServer
    {
        static X509Certificate serverCertificate = null;
        // The certificate parameter specifies the name of the file
        // containing the machine certificate.
        public static void RunServer(string certificate)
        {
            serverCertificate = X509Certificate.CreateFromCertFile(certificate);
            // Create a TCP/IP (IPv4) socket and listen for incoming connections.
            TcpListener listener = new TcpListener(IPAddress.Any, 8080);
            listener.Start();
            while (true)
            {
                Console.WriteLine("Waiting for a client to connect...");
                // Application blocks while waiting for an incoming connection.
                // Type CNTL-C to terminate the server.
                TcpClient client = listener.AcceptTcpClient();
                ProcessClient(client);
            }
        }
        static void ProcessClient (TcpClient client)
        {
            // A client has connected. Create the
            // SslStream using the client's network stream.
            SslStream sslStream = new SslStream(
                client.GetStream(), false);
            // Authenticate the server but don't require the client to authenticate.
            try
            {
                sslStream.AuthenticateAsServer(serverCertificate, 
                clientCertificateRequired: false, 
                SslProtocols.Ssl3,  // ВОТ ЗДЕСЬ ВНЕДРЕН КОД, КОТОРЫЙ СЛЕДУЕТ ТРАКТОВАТЬ КАК СЛАБОЕ КОНФИГУРИРОВАНИЕ, ПРИВОДЯЩЕЕ К УЯЗВИМОСТИ
                checkCertificateRevocation: true);


                // Write a message to the client.
                byte[] message = Encoding.UTF8.GetBytes("Hello from the server.<EOF>");
                Console.WriteLine("Sending hello message.");
                sslStream.Write(message);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine ("Authentication failed - closing the connection.");
                sslStream.Close();
                client.Close();
                return;
            }
            finally
            {
                // The client stream will be closed with the sslStream
                // because we specified this behavior when creating
                // the sslStream.
                sslStream.Close();
                client.Close();
            }
        }
        public static int Main(string[] args)
        {
            string certificate = null;
            certificate = args[0];
            SslTcpServer.RunServer (certificate);
            return 0;
        }
    }
}
```

### Пробная сборка кода теста

Выполнить `dotnet build`. В выводимых сборочной системой сообщениях вы в т.ч. увидите предупреждение компилятора следующего характера:

```bash
/home/user/svace/Program.cs(42,101): warning CS0618: 'SslProtocols.Ssl3' is obsolete: 'SslProtocols.Ssl3 has been deprecated and is not supported.' [/home/user/svace/svace.csproj]
```

а также сообщение:
```
Build succeeded.
```

### Сборка теста под контролем svace

Сборка и анализ осуществляются в соответствии с обычными правилами сборки и анализа кода с помощью svace:

```bash
/PATH/TO/SVACE/bin/svace init
/PATH/TO/SVACE/bin/svace build dotnet build
/PATH/TO/SVACE/bin/svace analyze
```

В выводе svace вы должны увидеть сообщение вида:

```bash
Analysis results:
Total warnings: 0
```

Свидетельствующее о том, что в представленных вами исходных текстах теста svace ошибок не выявил. А должен был бы выявить слабой значением параметра в функции AuthenticateAsServer.

## Пример создания теста для исходного текста на ЯП C/С++

### Поиск кода, некорректное конфигурирование которого может привести к уязвимости создаваемого ПО - хардкод в исходных текстах пароля доступа к серверу СУБД 

В ходе анализа библиотеки `libpq`, входящей в состав СУБД [postgres](https://github.com/postgres/postgres) и предоставлюящей стандартизованный набор классов для организации доступа к СУБД непосредственно из приложения (а также написания собственно postgres-клиента, частным и наиболее популярным примером которого является клиент `psql`), выявлено, что сдандартный конструктор класса `PQconnectdb`, отвечающего за соединение в целом, принимает на вход строку с описанием параметров соединения, одним из которых может являться ключ `password`. Присутствие данного ключа и соответственно заданного в строке соединения пароля скорее всего будет свидетельствовать о грубом нарушении правил создания безопасного приложения, запрещающих использование хардкод-паролей для организации доступа к чувствительной информации.

### Подготовка и запуск контейнера для сборки и анализа кода

Пример докер-файла:

```Dockerfile
FROM ubuntu:22.04

#Set Timezone or get hang during the docker build...
ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt update
RUN apt install -y vim git make clang-12 zlib1g-dev libreadline-dev bison flex
RUN git clone --depth=1 --single-branch --branch=REL_14_STABLE https://github.com/postgres/postgres

CMD /bin/bash
```

Пример команд сборки образа и запуска контейнера (с доступностью сети хоста для взаимодействия с сервером лицензий svace):

```bash
dotnet build -t c_svace_test0 -f Dockerfile .
docker run --network=host -it --rm --name=pnm_test1  -v ~/svace_prozelites:/svace_prozelites ub22_pg
```

### Подготовка кода теста

**Сперва стоит поискать какой-то готовый тестовый код, который использует интересующий нас класс, и изменить его, а не писать логику с нуля!**

Если поискать существующие тесты для postgres, то часть стандартных тестов найдётся в каталоге `postgres/src/test/examples/`. Разумно всегда начинать с самого первого теста - `testlibpq.c`. В нём мы [видим](https://github.com/postgres/postgres/blob/master/src/test/examples/testlibpq.c) функцию `main`, формирующую строку соединения и вызывающую конструктор `PQconnectdb(conninfo)` с данной строкой соединения в качестве параметра. Соответственно для минимизации теста всё, что расположено ниже данной команды, скорее всего можно удалить без ущерба для качества кода в целом (это всегда нужно проверять - наши тестовые примеры не должны содержать каких-либо ошибок кроме той, которую мы собственно и пытаемся выделить). Удалим код и добавим в строку подключения ключ ` password = VERYBAD `

```c
#include <stdio.h>
#include <stdlib.h>
#include "libpq-fe.h"

int
main(int argc, char **argv)
{
	const char *conninfo;
	PGconn	   *conn;
	
	/*
	 * If the user supplies a parameter on the command line, use it as the
	 * conninfo string; otherwise default to setting dbname=postgres and using
	 * environment variables or defaults for all other connection parameters.
	 */
	if (argc > 1)
		conninfo = argv[1];
	else
		conninfo = "dbname = postgres  password = VERYBAD"; //ДОБАВЛЕННЫЙ НАМИ ХАРДКОД-ПАРОЛЬ

	/* Make a connection to the database */
	conn = PQconnectdb(conninfo);
}
```

Казалось бы сборка данного теста будет очень простой - небольшой код, минимум заголовочных файлов. Однако именно подключение `libpq-fe.h` тянет за собой длинную цепочку необходимых инклюдов, восстановить которую самому достаточно сложно. 

Соответственно можно пойти двумя путями:

1. Осуществить сборку данного теста просто выполнив `make` в каталоге тестов. Основной минус - для того чтобы сборка выполнилась успешно вам потребуется собрать собственно основной postgres. А это достаточно ресурсоёмкая операция, и конечно же нам хотелось бы её избежать при формировании комплекта тестов. Если же не собрать postgres заранее, в результате выполнения `make` мы увидим лог сборки, оканчивающийся ошибкой компоновщика вида:

```bash
$ cd postgres 
$ CC=/usr/bin/clang-12 ./configure #Выполняем configure для postgres в целом, выбирая в качестве компилятора установленный в контейнер при создании образа компилятор clang-12
$ cd src/test/examples #Переходим в каталог тестов
$ make

...
/usr/bin/ld: cannot find -lpgcommon: No such file or directory
/usr/bin/ld: cannot find -lpgport: No such file or directory
/usr/bin/ld: cannot find -lpq: No such file or directory
/usr/bin/ld: cannot find -lpgcommon: No such file or directory
/usr/bin/ld: cannot find -lpgport: No such file or directory
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make: *** [../../../src/Makefile.global:795: testlibpq] Error 1

```

2. Попробовать всё таки самостоятельно сформировать минимальную команду сборки ровно одной единицы трансляции - минимизированного нами файла `testlibpq.c`. Универсального решения данной задачи не существует, однако в данном случае мы поставим эксперимент, который завершится удачно. Обратим внимание на вывод команды `make`, которую мы пытались выполнить ранее - а именно на попытку компиляции именно единицы трансляции `testlibpq.c`. Как видим, именно её компиляция (без компоновки) выполнена успешно:

```bash
/usr/bin/clang-12 -Wall -Wmissing-prototypes -Wpointer-arith -Wdeclaration-after-statement -Werror=vla -Werror=unguarded-availability-new -Wendif-labels -Wmissing-format-attribute -Wformat-security -fno-strict-aliasing -fwrapv -Wno-unused-command-line-argument -Wno-compound-token-split-by-macro -O2 -I../../../src/interfaces/libpq -I../../../src/include  -D_GNU_SOURCE   -c -o testlibpq.o testlibpq.c

И здесь нет сообщения об ошибке - начинается выполнение следующей команды!
...
```

### Пробная сборка кода теста

Соответственно мы можем использовать именно данную строку компиляции самостоятельно (удалив из неё все флаги, в точном предназначении которых не разбираемся, а также флаги управления предупреждениями компилятора `-W..`, убрав оптимизации `-O0`, и оставив пути к инклюдам) и проверить, что компиляция выполняется успешно (создается объектный файл testlibpq.o):

```bash
$ /usr/bin/clang-12 -O0 -I../../../src/interfaces/libpq -I../../../src/include  -D_GNU_SOURCE   -c -o testlibpq.o testlibpq.c
$ ll | grep testlibpq.o
-rw-r--r-- 1 root root 3010 Nov 15 15:27 testlibpq.o
```

### Сборка теста под контролем svace

Сборка и анализ осуществляются в соответствии с обычными правилами сборки и анализа кода с помощью svace:

```bash
/PATH/TO/SVACE/bin/svace init
/PATH/TO/SVACE/bin/svace build /usr/bin/clang-12 -O0 -I../../../src/interfaces/libpq -I../../../src/include  -D_GNU_SOURCE   -c -o testlibpq.o testlibpq.c
/PATH/TO/SVACE/bin/svace analyze
```

В выводе svace вы должны увидеть сообщение вида:

```bash
Analysis results:
Total warnings: 0
```

Свидетельствующее о том, что в представленных вами исходных текстах теста svace ошибок не выявил. А должен был бы выявить слабой значением параметра в функции AuthenticateAsServer.
