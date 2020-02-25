# Sample Gelf Message Generator
A simple command line application that generates sample messages and sends them to Graylog over GELF TCP.
A random delay is added between messages. The delay varies over time, to make the traffic appear more like
real traffic. 

The values for most fields sent in (including IP, Port, HTTP code, and HTTTP method fields are randomly generated). 
This is useful when generating charts and graphs, and performing GEO-IP lookups.

## Installation
1) Run `mvn package`
2) Run `java -jar gelf-sample-data-1.0-SNAPSHOT-shaded.jar` to start the application.

You can optionally use the [gelf-sample-data.service](gelf-sample-data.service) systemd service template to run the 
application as a daemon.

## Configuration
The following configuration options are supported with environment variables:

* Hostname to send messages to: `GELF_SAMPLE_HOSTNAME` (defaults to: `localhost`)
* Port to connect on: `GELF_SAMPLE_PORT` (defaults to: `12201`)
* Maximum time in milliseconds to wait between sending messages: `GELF_SAMPLE_MAX_SLEEP_TIME` (defaults to: `100` ms)
* Don't pause at all between messages: `GELF_SAMPLE_NO_SLEEP` (defaults to: `false`)
