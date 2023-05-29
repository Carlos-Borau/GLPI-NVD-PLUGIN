function addEventListeners() {
    var selectVendor        = document.getElementById("nvd_cpe_vendor_dropdown");
    var selectProduct       = document.getElementById("nvd_cpe_product_dropdown");
    var selectVendorTerms   = document.getElementById("nvd_cpe_vendor_terms_dropdown");
    var selectProductTerms  = document.getElementById("nvd_cpe_product_terms_dropdown");
    var filterVendor        = document.getElementById("nvd_cpe_vendor_filter");
    var filterProduct       = document.getElementById("nvd_cpe_product_filter");
    var applyVendorFilter   = document.getElementById("nvd_cpe_apply_vendor_filter");
    var applyProductFilter  = document.getElementById("nvd_cpe_apply_product_filter");
    var clearVendorFilter   = document.getElementById("nvd_cpe_clear_vendor_filter");
    var clearProductFilter  = document.getElementById("nvd_cpe_clear_product_filter");
    var vendorHiddenList    = document.getElementById("nvd_cpe_vendor_hidden_list");
    var productHiddenList   = document.getElementById("nvd_cpe_product_hidden_list");

    addSugestedTermsEventListener(selectVendorTerms, filterVendor);
    addSugestedTermsEventListener(selectProductTerms, filterProduct);

    addFilterApplyEventListener(filterVendor, selectVendorTerms, applyVendorFilter, selectVendor, vendorHiddenList, filterProduct, selectProductTerms, selectProduct, productHiddenList);
    addFilterApplyEventListener(filterProduct, selectProductTerms, applyProductFilter, selectProduct, productHiddenList);

    addFilterClearEventListener(filterVendor, selectVendorTerms, clearVendorFilter, selectVendor, vendorHiddenList, filterProduct, selectProductTerms, selectProduct, productHiddenList);
    addFilterClearEventListener(filterProduct, selectProductTerms, clearProductFilter, selectProduct, productHiddenList);

    selectVendor.addEventListener("change", function(){

        var vendor = this.value;

        var http = new XMLHttpRequest();

        http.onreadystatechange = function(){
            if(this.readyState == 4 && this.status == 200){
                var response = JSON.parse(this.responseText);

                selectProduct.innerHTML = selectProduct.firstChild.outerHTML;

                var prodList = '';

                for (product of response){

                    prodList += `${product} `;

                    addOption(selectProduct, product);
                }

                productHiddenList.innerHTML = prodList;
            }
        }

        script_url = window.location.origin + "/glpi/plugins/nvd/front/softwarecpe.form.php?vendor=" + vendor;
        http.open('GET', script_url);
        http.send();
    });
}

function addSugestedTermsEventListener(select, filter) {

    select.addEventListener("change", function(){

        var term = this.value;
        filter.value = term;
    });
}

function addFilterApplyEventListener(filter, filterSelect, apply, select, hiddenList, otherFilter=null, otherFilterSelect=null, otherSelect=null, otherHiddenList=null) {

    apply.addEventListener("click", function(){

        resetSelects(select, otherSelect, otherHiddenList);

        var term = filter.value;
        var pattern = new RegExp(".*" + escapeRegExp(term) + ".*");

        var items = hiddenList.innerHTML.split(" ");

        items.forEach(item => {

            if (pattern.test(item)) { 

                addOption(select, item);
             }
        })

        resetFilters(filter, filterSelect, otherFilter, otherFilterSelect);
    });
}

function addFilterClearEventListener(filter, filterSelect, clear, select, hiddenList, otherFilter=null, otherFilterSelect=null, otherSelect=null, otherHiddenList=null) {

    clear.addEventListener("click", function(){

        resetSelects(select, otherSelect, otherHiddenList);
        resetFilters(filter, filterSelect, otherFilter, otherFilterSelect, true);

        var items = hiddenList.innerHTML.split(" ");

        items.forEach(item => {

            addOption(select, item);
        })
    });
}

function addOption(select, value) {

    var option = document.createElement('option');
    option.value = value;
    option.innerHTML = value;

    select.appendChild(option);
}

function resetSelects(select, otherSelect, otherHiddenList=null) {

    select.innerHTML = select.firstChild.outerHTML;
    select.value = '-DEFAULT-';

    if (otherSelect !== null && otherHiddenList !== null) {
        otherSelect.innerHTML = otherSelect.firstChild.outerHTML;
        otherSelect.value = '-DEFAULT-';
        otherHiddenList.innerHTML = '';
    }
}

function resetFilters(filter, filterSelect, otherFilter, otherFilterSelect, removeFilterText=false) {

    filterSelect.value = '-DEFAULT-';

    if (removeFilterText) {
        filter.value = '';
    }

    if (otherFilter !== null && otherFilterSelect !== null){
        otherFilterSelect.value = '-DEFAULT-';
        otherFilter.value = '';
    }
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function changeSelectedValue(select, value) {
    select.value = value;
}