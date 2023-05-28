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
}

?>