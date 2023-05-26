function addEventListeners() {
    var selectVendor        = document.getElementById("nvd_cpe_vendor_dropdown");
    var selectProduct       = document.getElementById("nvd_cpe_product_dropdown");
    var selectVendorTerms   = document.getElementById("nvd_cpe_vendor_terms_dropdown");
    var selectProductTerms  = document.getElementById("nvd_cpe_product_terms_dropdown");
    var vendorHiddenList    = document.getElementById("vendor_hidden_list");
    var productHiddenList   = document.getElementById("product_hidden_list");

    selectVendor.addEventListener("change", function(){
        var vendor = this.value;

        var http = new XMLHttpRequest();

        http.onreadystatechange = function(){
            if(this.readyState == 4 && this.status == 200){
                var response = JSON.parse(this.responseText);

                var outDropdown = `<option disabled selected value>-- ` + __(`SELECT A PRODUCT`) + ` --</option>`;
                var outHidden = ``;

                for (product of response){
                    outDropdown += `<option value="${product}">${product}</option>`;
                    outHidden += `${product} `;
                }

                selectProduct.innerHTML = outDropdown;
                productHiddenList.innerHTML = outHidden;
            }
        }

        script_url = window.location.origin + "/glpi/plugins/nvd/front/softwarecpe.form.php?vendor=" + vendor;
        http.open('GET', script_url);
        http.send();
    });

    selectVendorTerms.addEventListener("change", function(){

        var term = this.value;
        var pattern = new RegExp(".*" + escapeRegExp(term) + ".*");
        var vendors = vendorHiddenList.innerHTML.split(' ');

        var out = `<option disabled selected value>-- ` + __(`SELECT A VENDOR`) + ` --</option>`;

        for (var i = 0; i < vendors.length; i++) {

            var vendor = vendors[i];

            if (pattern.test(vendor)) {
                out += `<option value="${vendor}">${vendor}</option>`;
            }
        }

        selectVendor.innerHTML = out;
    });

    selectProductTerms.addEventListener("change", function(){

        var term = this.value;
        var pattern = new RegExp(".*" + escapeRegExp(term) + ".*");
        var products = productHiddenList.innerHTML.split(' ');

        var out = `<option disabled selected value>-- ` + __(`SELECT A VENDOR`) + ` --</option>`;

        for (var i = 0; i < products.length; i++) {

            var product = products[i];

            if (pattern.test(product)) {
                out += `<option value="${product}">${product}</option>`;
            }
        }

        selectProduct.innerHTML = out;
    });
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); // $& means the whole matched string
  }