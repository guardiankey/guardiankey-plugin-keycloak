<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper" style="text-align:center; padding: 1.5em 0;">
                <p>${msg("doLogIn")}...</p>
            </div>
            <form id="kc-gktinc-form" action="${url.loginAction}" method="post" style="display:none;">
                <input type="hidden" id="gktinc_username" name="username" value="${gktincUsername!''}" />
                <input type="hidden" id="gktinc_solution" name="gktinc_solution" value="" />
            </form>
        </div>
        <script>
            ${gktincConfig?no_esc}
        </script>
        <script src="https://guardiankey.io/js/gktinc-setup-latest.js?v=9"></script>
        <script>
            gktinc_init(
                gktinc_config,
                document.getElementById('kc-gktinc-form'),
                document.getElementById('gktinc_username'),
                true
            );
        </script>
    </#if>
</@layout.registrationLayout>
