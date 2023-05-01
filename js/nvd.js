function addEventListenerToVendorSelect(server) {
    var selectVendor = document.querySelector("#nvd_cpe_vendor_dropdown");
    var selectProduct = document.querySelector("#nvd_cpe_product_dropdown");

    selectVendor.addEventListener("change", function(){
        var vendor = this.value;

        var http = new XMLHttpRequest();

        http.onreadystatechange = function(){
            if(this.readyState == 4 && this.status == 200){
               var response = JSON.parse(this.responseText);

               var out = `<option disabled selected value>-- ` + __(`SELECT A PRODUCT`) + ` --</option>`;

               for (product of response){
                out += `<option value="${product}">${product}</option>`;
               }

               selectProduct.innerHTML = out;
            }
        }

        script_url = window.location.origin + "/glpi/plugins/nvd/front/softwarecpe.form.php?vendor=" + vendor;
        http.open('GET', script_url);
        http.send();
    });
}