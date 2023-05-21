# NVD Plugin for GLPI

## Description

The NVD plugin for GLPI has been developed as an open source project with its main objective being providing a mechanism for the GLPI framework to monitor known software vulnerabilities found on the IT assets managed by GLPI. The plugin automatically gathers software installations (programs, manufacturers and versions) from the GLPI database and queries the NVD database for vulnerabilities associated with such configurations. Found vulnerabilities are stored in the GLPI database along their corresponding relations with the vulnerable installations so that they can be later visualized by users.

## Visualization of vulnerabilities

Stored vulnerabilities can be visualized from three different places within GLPI:

- **Dashboard**: From this view every vulnerability present on any device managed by GLPI is shown in the form of a table with a row for every vulnerability and each column containing the CVE identifier, description, CVSS score, severity and a list of the devices in which the vulnerability can be found.

- **Device Tab**: This view contains every vulnerability present on a scpecific device. Version 1.0.0 of the NVD plugin only suports device views for *Computers* and *Phones* in the GLPI *Assets* menu. The information shown in this view is similar to that shown for the dashboard view, except for the devices column which is replaced by a column containing every software application on the selected device in which that row's vulnerability is present.

- **Software Tab**: This view contains every vulnerability associated with a scpecific software application and can be accessed through the *Software* tab in the GLPI *Assets* menu. The information shown in this view is similar to that shown for the device view, except for the applications column which is replaced by a column containing every version of the selected software that is vulnerable to that row's vulnerability.