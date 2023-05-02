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

    //pluginNvdRegisterTasks();
}

/**
 * Manages the creation of tables required by the plugin on the GLPI database schema
 *
 * Created tables are:
 * - glpi_plugin_nvd_vulnerabilities
 * - glpi_plugin_nvd_vulnerable_versions
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
     *      -description = Summary of the vulnerability's characteristics and behavior
     *      -nvd_ref = Reference to the vulnerability's entry on the nvd database
     *      -severity = Vulnerability's severity (NONE, LOW, MEDIUM, HIGH, CRITICAL)
     *      -exploitability_score = Vulneravility's facility to be exploited [0.0-10.0]
     *      -impact_score = Vulneravility's capability to impact an asset once exploited [0.0-10.0]
     **********************************************************************************************/
    if(!$DB->tableExists('glpi_plugin_nvd_vulnerabilities')){

        $query = "CREATE TABLE `glpi_plugin_nvd_vulnerabilities` (
                    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `cve_id` VARCHAR(16) UNIQUE,
                    `description` VARCHAR(1024),
                    `severity` VARCHAR(16),
                    `base_score` FLOAT(24),
                    `exploitability_score` FLOAT(24),
                    `impact_score` FLOAT(24),
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

        $DB->queryOrDie($query, $DB->error());
    }

    /***********************************************************************************************
     * Table:   glpi_plugin_nvd_vulnerable_versions
     * Stores:  Relations between software versions and known vulnerabilities
     * Fields:
     *      -id = Numerical autoincrement ID
     *      -vuln_id = ID of the vulnerability in the glpi_plugin_nvd_vulnerabilities table
     *      -softwareversions_id = ID of the software version in the glpi_softwareversions table
     **********************************************************************************************/ 
    if(!$DB->tableExists('glpi_plugin_nvd_vulnerable_versions')){

        $query = "CREATE TABLE `glpi_plugin_nvd_vulnerable_versions` (
                    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    `vuln_id` INT UNSIGNED NOT NULL,
                    `softwareversions_id` INT UNSIGNED NOT NULL,
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
     *      -last_consult_date = ISO-8061 date/time formated date of the last consult
     **********************************************************************************************/ 
    if(!$DB->tableExists('glpi_plugin_nvd_config')){

        $query = "CREATE TABLE `glpi_plugin_nvd_config` (
                    `api_key` VARCHAR(63) NOT NULL,
                    `last_consult_date` VARCHAR(63),
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