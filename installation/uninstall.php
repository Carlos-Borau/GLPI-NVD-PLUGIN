<?php

/**
 * Manages the uninstallation of the NVD plugin from GLPI
 *
 * Uninstallation steps are:
 * - Deletion of plugin tables from the GLPI database schema
 *
 * @since 1.0.0
 *
 * @return void
 */
function pluginNvdUninstall(){

    pluginNvdDropTables();

}

/**
 * Manages the deletion of tables required by the plugin from the GLPI database schema
 *
 * Dropped tables are:
 * - glpi_plugin_nvd_vulnerabilities
 * - glpi_plugin_nvd_vulnerability_descriptions
 * - glpi_plugin_nvd_vulnerability_configurations
 * - glpi_plugin_nvd_vulnerable_versions
 * - glpi_plugin_nvd_cpe_software_associations
 * - glpi_plugin_nvd_config
 *
 * @since 1.0.0
 *
 * @return void
 */
function pluginNvdDropTables(){

    global $DB;

    $tables = [
        'vulnerabilities',
        'vulnerability_descriptions',
        'vulnerability_configurations',
        'vulnerable_versions',
        'cpe_software_associations',
        'config'
    ];

    foreach ($tables as $table) {

        $tablename = 'glpi_plugin_nvd_' . $table;

        if($DB->tableExists($tablename)){

            $query = "DROP TABLE `$tablename`";

            $DB->queryOrDie($query, $DB->error());
        }
    }
}


?>