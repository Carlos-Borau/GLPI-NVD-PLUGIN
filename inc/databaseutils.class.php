<?php

class PluginNvdDatabaseutils {

    /**
     * Queries the GLPI database and returns the default language from settings
     * 
     * @since 1.0.0
     * 
     * @return string    GLPI default language
     */
    public static function getGLPILanguage() {

        global $DB;

        /***********************************************************************************************
         * Request GLPI default language from settings
         * 
         *  SELECT value
         *  FROM glpi_configs
         *  WHERE name = language
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'value',
                             'FROM' => 'glpi_configs',
                             'WHERE' => ['name' => 'language']]);

        if ($res->numrows() != 0) {

            $row = $res->current();

            return $row['value'];
        }

        return null;
    }

    /**
     * Combine values from database query result into an array
     * 
     * @since 1.0.0
     * 
     * @param 
     * 
     * @return array    Array values
     */
    public static function pushResToArray($res, $value, $key=NULL) {

        $array = [];

        if ($key == NULL) {

            foreach ($res as $id => $row) {
                $array[] = $row[$value];
            }

        } else {

            foreach ($res as $id => $row) {
                $array[$row[$key]] = $row[$value];
            }
        }

        return $array;
    }

    /**
     * Queries the GLPI database and returns the current autoincrement value for the given table 
     * 
     * @since 1.0.0
     * 
     * @param string $table     Name of the table for which to query the autoincrement value 
     * 
     * @return int
     */
    public static function getNextId($table) {

        global $DB;

        /***********************************************************************************************
         * Request autoincrement value for $table
         * 
         *  SELECT AUTO_INCREMENT
         *  FROM INFORMATION_SCHEMA.TABLES
         *  WHERE TABLE_SCHEMA = glpi AND TABLE_NAME = $table
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'AUTO_INCREMENT',
                             'FROM' => 'INFORMATION_SCHEMA.TABLES',
                             'WHERE' => ['TABLE_SCHEMA' => 'glpi',
                                         'TABLE_NAME' => $table]]);

        if ($res->numrows() == 1) {

            $row = $res->current();
            
            return $row['AUTO_INCREMENT'];
        }
        
        return null;
    }

    /**
     * Transform OS related info IDs to actual values
     * 
     * @since 1.0.0
     * 
     * @param array $row Array containing OS name, version, kernel version and service pack IDs on the GLPI database
     * 
     * @return array     Array containing OS name, version, kernel, kernel version and service pack
     */
    public static function requestOSdata($row) {

        global $DB;

        $OS_ID                  = $row['operatingsystems_id'];
        $OS_version_ID          = $row['operatingsystemversions_id'];
        $OS_kernel_version_ID   = $row['operatingsystemkernelversions_id'];
        $OS_service_pack_ID     = $row['operatingsystemservicepacks_id'];

        /***********************************************************************************************
         * Request operating system name
         * 
         *  SELECT name
         *  FROM glpi_operatingsystems
         *  WHERE id = $OS_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_operatingsystems',
                             'WHERE' => ['id' => $OS_ID]]);

        $name = ($res->numrows() == 1) ? ($res->current())['name'] : null;

        /***********************************************************************************************
         * Request operating system version
         * 
         *  SELECT name
         *  FROM glpi_operatingsystemversions
         *  WHERE id = $OS_version_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_operatingsystemversions',
                             'WHERE' => ['id' => $OS_version_ID]]);

        $version = ($res->numrows() == 1) ? ($res->current())['name'] : null;

        /***********************************************************************************************
         * Request operating system version
         * 
         *  SELECT name, glpi_operatingsystemkernelversions
         *  FROM glpi_operatingsystemkernelversions
         *  WHERE id = $OS_kernel_version_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['name', 'operatingsystemkernels_id'],
                             'FROM' => 'glpi_operatingsystemkernelversions',
                             'WHERE' => ['id' => $OS_kernel_version_ID]]);

        $kernelVersion  = ($res->numrows() == 1) ? ($res->current())['name'] : null;
        $OS_kernel_ID   = ($res->numrows() == 1) ? ($res->current())['operatingsystemkernels_id'] : 0;

        /***********************************************************************************************
         * Request operating system kernel
         * 
         *  SELECT name
         *  FROM glpi_operatingsystemkernels
         *  WHERE id = $OS_kernel_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_operatingsystemkernels',
                             'WHERE' => ['id' => $OS_kernel_ID]]);

        $kernel = ($res->numrows() == 1) ? ($res->current())['name'] : null;

        /***********************************************************************************************
         * Request operating system service pack
         * 
         *  SELECT name
         *  FROM glpi_operatingsystemservicepacks
         *  WHERE id = $OS_service_pack_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_operatingsystemservicepacks',
                             'WHERE' => ['id' => $OS_service_pack_ID]]);

        $servicePack = ($res->numrows() == 1) ? ($res->current())['name'] : null;

        return [$name, $version, $kernel, $kernelVersion, $servicePack];
    }
}

?>