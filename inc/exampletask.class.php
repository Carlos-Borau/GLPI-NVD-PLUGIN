<?php


class PluginNvdExampletask extends CommonDBTM {

    /**
    * Check if can view item
    *
    * @return boolean
    */
    static function canView() {
        return Config::canView();
    }

    function getTabNameForItem(CommonGLPI $item, $withtemplate=0) {

        return self::createTabEntry('ExampleTask');
    }

    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {

        self::cronExampleTask();

        return true;
    }


    public static function cronExampleTask($task=NULL){

        global $DB;

        $req = $DB->request(['SELECT' => 'value', 'FROM' => 'glpi_plugin_nvd_prueba']);

        if($req->numrows() > 0){

            echo 'Hay algo creado <br>';

            $row = $req->current();

            $value = $row['value'];

            echo "Valor actual: $value<br>";

            $DB->update(
                'glpi_plugin_nvd_prueba', [
                   'value'      => $value + 1
                ],
                ['value' => $value]
             );

        } else {

            echo 'No hay nada creado <br>';

            $DB->insert('glpi_plugin_nvd_prueba', ['value' => 0]);
        }

        return true;
    }

}


?>