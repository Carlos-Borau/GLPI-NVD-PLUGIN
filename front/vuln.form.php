<style>
    <?php include ("../nvd.css"); ?>
</style>

<?php

include ("../../../inc/includes.php");

// Check if plugin is activated...
// $plugin = new Plugin();
// if (!$plugin->isInstalled('nvd') || !$plugin->isActivated('nvd')) {
//    Html::displayNotFoundError();
// }

if ($_POST && isset($_POST['part']) && isset($_POST['vendor']) && isset($_POST['product']) && isset($_POST['version'])) {

    $part       = $_POST["part"];
    $vendor     = $_POST["vendor"];
    $product    = $_POST["product"];
    $version    = $_POST["version"];

    $cpe = new PluginNvdCpe($part, $vendor, $product, $version);

    $cpe_name = $cpe->get_CPE_WFN();

    echo $cpe_name . '<br>';

    $nvd = new PluginNvdConnection();

    /**
    * 
    * @todo This should eventually go away
    */ 
    $nvd::setApiKey('e5cd5b7b-7288-4f00-9a45-d47a2f9942b2');

    echo $nvd::getApiKey() . '<br>';

    $nvd->setUrlParams($cpe_name, true);

    echo $nvd->getCompleteUrl() . '<br>';

    $records = $nvd->requestNvdRecords();
    echo getVulnFormatedTable(json_decode($records, true));

    // Html::redirect("{$CFG_GLPI['root_doc']}/plugins/nvd/front/vuln.php");

} else {
    Html::redirect("{$CFG_GLPI['root_doc']}/plugins/nvd/front/vuln.php");
}

function getVulnFormatedTable($records) {

    $resultsPerPage     = $records['resultsPerPage'];
    $startIndex         = $records['startIndex'];
    $totalResults       = $records['totalResults'];
    $format             = $records['format'];
    $version            = $records['version'];
    $timestamp          = $records['timestamp'];
    $vulnerabilities    = $records['vulnerabilities'];

    echo 'Retrieved ' . $totalResults . ' records from NVD database <br>';

    $table =    '<table class="center">';
    $table .=   '<colgroup><col width="10%"/><col width="20%"/><col width="70%"/></colgroup>';
    $table .=   '<tr>';
    $table .=   '<th>CVE-ID</th>';
    $table .=   '<th>' . __('Publish Date') . '</th>';
    $table .=   '<th>' . __('Description') . '</th>';
    $table .=   '</tr>';

    foreach($vulnerabilities as $v) {

        $table .= '<tr>';

        $id             = $v['cve']['id'];
        $publishDate    = $v['cve']['published'];
        $descriptions   = [];

        foreach($v['cve']['descriptions'] as $d){
            $descriptions[$d['lang']] = $d['value'];
        }

        $table .= '<td>' . $id . '</td>';
        $table .= '<td>' . $publishDate . '</td>';
        $table .= '<td>' . $descriptions['en'] . '</td>';

        $table .= '</tr>';
    }

    $table .= '</table>';

    return $table;
}
    
?>