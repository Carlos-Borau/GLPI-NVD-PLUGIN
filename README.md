# NVD Plugin for GLPI

## Description

The NVD plugin for GLPI has been developed as an open source project with its main objective being providing a mechanism for the GLPI framework to monitor known software vulnerabilities found on the IT assets managed by GLPI. The plugin automatically gathers software installations (programs, manufacturers and versions) from the GLPI database and queries the NVD database for vulnerabilities associated with such configurations. Found vulnerabilities are stored in the GLPI database along their corresponding relations with the vulnerable installations so that they can be later visualized by users.

## Installation

1. Download the contents of this repository via compressed file download or git client repository clone.
2. If the first option was chosen extract the contents form the zip file.
3. Place the downloaded contents inside a directory named "**nvd**".
4. Move the "**nvd**" directory to the "*plugins*" directory located inside the GLPI root folder.
5. Access the GLPI instance via its web interface. and enter the plugins configuration menu (*Configuration* -> *Plugins*).
6. Locate the entry corresponding to the NVD plugin in the plugins table and install it by clicking the rightmost button (icon of folder with '+' symbol)
7. Enable the plugin by clicking the switch placed on the left of the uninstall button (formerly install button).
8. Once the switch turns green the plugin will be installed and enabled.

## Configuration

1. In order to query the NVD database for vulnerabilities, the corresponding API KEY needs to be set by accesing the plugin configuration menu (*Configuration* -> *General* -> *NVD Plugin*).
2. In order to correctcly compose the CPE names of the different programs to search for vulnerabilities they need to be manually associated with the corresponding *vendor* and *product* names for the CPE estandar. Thiscan be archieved with the interface provided on the *CPE Associations* tab located in a software's view.

## Sugestions

The plugin uses a scheduled task to query the NVD database for vulnerabilities related to the different software and operating system versions installed on the devices managed by GLPI. This task may span its execution for tens of minutes, even a few hours provided a large enough inventory. It is recomended to increase the maximum execution time for tasks on the web server that runs the GLPI instance to allow this code to fully execute.

## Visualization of vulnerabilities

Stored vulnerabilities can be visualized from three different places within GLPI:

- **Dashboard**: This view contains every vulnerability present on any device managed by GLPI. The view is divided into two different sections containing vulnerabilities ralated to software versions and OS versions respectively. These vulnerabilities are displayed in the form of a table with a row for every vulnerability and each column containing the CVE identifier, description, CVSS score, severity and a list of the devices in which the vulnerability can be found.

- **Device Tab**: This view contains every vulnerability present on a scpecific device. Version 1.0.0 of the NVD plugin only suports device views for *Computers* and *Phones* in the GLPI *Assets* menu. The view is also divided into two different sections containing vulnerabilities ralated to the versions of the programs installed on the deevice and its operating system respectively. The information shown in this view is similar to that shown for the dashboard view, except for the devices column, which is replaced in the first section (Software vulnerabilities) by a column containing every software application on the selected device in which that row's vulnerability is present and is missing in the seccond section (OS Vulnerabilities).

- **Software Tab**: This view contains every vulnerability associated with a scpecific software application and can be accessed through the *Software* tab in the GLPI *Assets* menu. The information shown in this view is similar to that shown for the device view, except for the applications column which is replaced by a column containing every version of the selected software that is vulnerable to that row's vulnerability.
