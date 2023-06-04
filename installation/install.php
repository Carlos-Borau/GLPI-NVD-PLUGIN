<?php

/**
 * Manages the installation of the NVD plugin to GLPI
 *
 * Installation steps are:
 * - Creation of plugin tables on the GLPI database schema
 * - Registration of tasks
 *
 * @since 1.0.0
 *
 * @return void
 */
function pluginNvdInstall(){

    pluginNvdCreateTables();

    pluginNvdRegisterTasks();
}

/**
 * Manages the creation of tables required by the plugin on the GLPI database schema
 *
 * Created tables are:
 * - glpi_plugin_nvd_vulnerabilities
 * - glpi_plugin_nvd_vulnerability_descriptions
 * - glpi_plugin_nvd_vulnerability_configurations
 * - glpi_plugin_nvd_vulnerable_software_versions
 * - glpi_plugin_nvd_vulnerable_system_versions
 * - glpi_plugin_nvd_cpe_software_associations
 * - glpi_plugin_nvd_config
 *
 * @since 1.0.0
 *
 * @return void
 */
function pluginNvdCreateTables(){

    global $DB;

    /***********************************************************************************************
     * Table:   glpi_plugin_nvd_vulnerabilities
     * Stores:  CVE reccords of vulnerabilities found on managed assets
     * Fields:
     *      -id = Numerical autoincrement ID
     *      -cve_id = Vulnerability ID on the CVE MITRE database
     *      -base_score = Vulnerability's CVSS base score
     *      -exploitability_score = Vulneravility's facility to be exploited [0.0-10.0]
     *      -impact_score = Vulneravility's capability to impact an asset once exploited [0.0-10.0]
     **********************************************************************************************/
    if(!$DB->tableExists('glpi_plugin_nvd_vulnerabilities')){

        $query = "CREATE TABLE `glpi_plugin_nvd_vulnerabilities` (
                    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `cve_id` VARCHAR(16) UNIQUE NOT NULL,
                    `base_score` FLOAT(24),
                    `exploitability_score` FLOAT(24),
                    `impact_score` FLOAT(24),
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        $DB->queryOrDie($query, $DB->error());
    }

    /***********************************************************************************************
     * Table:   glpi_plugin_nvd_vulnerability_descriptions
     * Stores:  Descriptions in different languages for stored vulnerabilities
     * Fields:
     *      -id = Numerical autoincrement ID
     *      -vuln_id = ID of the vulnerability in the glpi_plugin_nvd_vulnerabilities table
     *      -language = ISO 639-1 language code
     *      -description = Summary of the vulnerability's characteristics and behavior
     **********************************************************************************************/
    if(!$DB->tableExists('glpi_plugin_nvd_vulnerability_descriptions')){

        $query = "CREATE TABLE `glpi_plugin_nvd_vulnerability_descriptions` (
                    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `vuln_id` INT UNSIGNED NOT NULL,
                    `language` CHAR(2),
                    `description` VARCHAR(8000),
                    CONSTRAINT `VULN_LANG` UNIQUE (`vuln_id`, `language`),
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        $DB->queryOrDie($query, $DB->error());
    }

    /***********************************************************************************************
     * Table:   glpi_plugin_nvd_vulnerability_configurations
     * Stores:  CPE software configurations for stored vulnerabilities
     * Fields:
     *      -id = Numerical autoincrement ID
     *      -vuln_id = ID of the vulnerability in the glpi_plugin_nvd_vulnerabilities table
     *      -vendor_name = Name of the software's vendor on the NIST CPE Dictionary
     *      -product_name = Name of the software on the NIST CPE Dictionary
     *      -update = List of CPE updates for the software configurations
     *      -edition = List of CPE software editions for the software configurations
     *      -target_sw = List of CPE target softwares for the software configurations
     *      -target_hw = List of CPE target hardwares for the software configurations
     **********************************************************************************************/
    if(!$DB->tableExists('glpi_plugin_nvd_vulnerability_configurations')){

        $query = "CREATE TABLE `glpi_plugin_nvd_vulnerability_configurations` (
                    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `vuln_id` INT UNSIGNED NOT NULL,
                    `vendor_name` VARCHAR(255),
                    `product_name` VARCHAR(255),
                    `update` VARCHAR(2047),
                    `edition` VARCHAR(2047),
                    `target_sw` VARCHAR(2047),
                    `target_hw` VARCHAR(2047),
                    CONSTRAINT `VULN_CONF` UNIQUE (`vuln_id`, `vendor_name`, `product_name`),
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        $DB->queryOrDie($query, $DB->error());
    }

    /***********************************************************************************************
     * Table:   glpi_plugin_nvd_vulnerable_software_versions
     * Stores:  Relations between software versions and known vulnerabilities
     * Fields:
     *      -id = Numerical autoincrement ID
     *      -vuln_id = ID of the vulnerability in the glpi_plugin_nvd_vulnerabilities table
     *      -softwareversions_id = ID of the software version in the glpi_softwareversions table
     **********************************************************************************************/ 
    if(!$DB->tableExists('glpi_plugin_nvd_vulnerable_software_versions')){

        $query = "CREATE TABLE `glpi_plugin_nvd_vulnerable_software_versions` (
                    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `vuln_id` INT UNSIGNED NOT NULL,
                    `softwareversions_id` INT UNSIGNED NOT NULL,
                    CONSTRAINT `VULN_VERSION` UNIQUE (`vuln_id`, `softwareversions_id`),
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        $DB->queryOrDie($query, $DB->error());
    }

    /***********************************************************************************************
     * Table:   glpi_plugin_nvd_vulnerable_system_versions
     * Stores:  Relations between operating system versions and known vulnerabilities
     * Fields:
     *      -id = Numerical autoincrement ID
     *      -vuln_id = ID of the vulnerability in the glpi_plugin_nvd_vulnerabilities table
     *      -system_configuration = Configuration of the vulnerable system containing CPE vendor and
     *          product names as well as its version
     **********************************************************************************************/ 
    if(!$DB->tableExists('glpi_plugin_nvd_vulnerable_system_versions')){

        $query = "CREATE TABLE `glpi_plugin_nvd_vulnerable_system_versions` (
                    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `vuln_id` INT UNSIGNED NOT NULL,
                    `system_configuration` VARCHAR(2047) NOT NULL,
                    CONSTRAINT `VULN_SYSTEM_VERSION` UNIQUE (`vuln_id`, `system_configuration`),
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        $DB->queryOrDie($query, $DB->error());
    }

    /***********************************************************************************************
     * Table:   glpi_plugin_nvd_cpe_software_associations
     * Stores:  CPE vendor and product names associated with each software managed by GLPI
     * Fields:
     *      -id = Numerical autoincrement ID
     *      -softwares_id = ID of the software in the glpi_softwares table
     *      -vendor_name = Name of the software's vendor on the NIST CPE Dictionary
     *      -product_name = Name of the software on the NIST CPE Dictionary
     **********************************************************************************************/ 
    if(!$DB->tableExists('glpi_plugin_nvd_cpe_software_associations')){

        $query = "CREATE TABLE `glpi_plugin_nvd_cpe_software_associations` (
                    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `softwares_id` INT UNSIGNED NOT NULL UNIQUE,
                    `vendor_name` VARCHAR(255),
                    `product_name` VARCHAR(255),
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        $DB->queryOrDie($query, $DB->error());
    }

    /***********************************************************************************************
     * Table:   glpi_plugin_nvd_config
     * Stores:  Stores a sinle row containing config values used when requesting CVE records
     * Fields:
     *      -api_key = NVD API KEY for querying the database API
     **********************************************************************************************/ 
    if(!$DB->tableExists('glpi_plugin_nvd_config')){

        $query = "CREATE TABLE `glpi_plugin_nvd_config` (
                    `api_key` VARCHAR(63) NOT NULL,
                    PRIMARY KEY (`api_key`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        $DB->queryOrDie($query, $DB->error());
    }
}

/**
 * Manages the registration of tasks required by the plugin
 *
 * Created tasks are:
 * - UpdateVulnTask
 *
 * @since 1.0.0
 *
 * @return void
 */
function pluginNvdRegisterTasks(){

    require_once(PLUGIN_NVD_DIR . '\inc\updatevuln.class.php');

    $res = CronTask::Register(
        'PluginNvdUpdatevuln',
        'UpdateVulnTask',
        (60 * 60),
        ['comment' => __('Task to update known vulnerabilities present on GLPI managed devices'), 'mode' => CronTask::MODE_EXTERNAL]
    );
}

?>