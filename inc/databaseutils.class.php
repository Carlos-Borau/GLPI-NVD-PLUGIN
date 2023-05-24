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

    
}

?>