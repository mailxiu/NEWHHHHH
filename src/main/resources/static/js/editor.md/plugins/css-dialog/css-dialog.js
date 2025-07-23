/*!
 * Code block dialog plugin for Editor.md
 *
 * @file        code-block-dialog.js
 * @author      pandao
 * @version     1.2.0
 * @updateTime  2015-03-07
 * {@link       https://github.com/pandao/editor.md}
 * @license     MIT
 */

(function() {

    var factory = function (exports) {
		var pluginName    = "css-dialog";
    
		// for CodeBlock dialog select
		var codeLanguages = exports.codeLanguages = {
			width         : ["长度", "100px;"],
			height        : ["高度", "100px;"],
			"border-radius" : ["圆角", "25px;"],
			border        : ["边框", "5px solid #575757;"],
			"background-color": ["背景色", "#00ff00;"],
			padding       : ["内边距", "10px 10px 10px 10px;"],
			margin  	  : ["外边距", "10px 10px 10px 10px;"],
			"font-size"    : ["字体大小", "20px;"],
			color          : ["字体颜色", "#ffffff;"],
			"font-weight"  : ["字体宽度", "700;"],
            "text-align"  : ["文字居中", "center;"],
		};

		exports.fn.cssDialog = function() {

			var _this       = this;
            var cm          = this.cm;
            var lang        = this.lang;
            var editor      = this.editor;
            var settings    = this.settings;
            var cursor      = cm.getCursor();
            var selection   = cm.getSelection();
            var classPrefix = this.classPrefix;
			var dialogName  = classPrefix + pluginName, dialog;
			var dialogLang  = lang.dialog.codeBlock;

			cm.focus();

            if (editor.find("." + dialogName).length > 0)
            {
                dialog = editor.find("." + dialogName);
                dialog.find("option:first").attr("selected", "selected");
                dialog.find("textarea").val(selection);

                this.dialogShowMask(dialog);
                this.dialogLockScreen();
                dialog.show();
            }
            else 
            {      
                var dialogHTML = "<div class=\"" + classPrefix + "code-toolbar\">" +
                                    "<div style='display: flex;align-items: center;'>"+
                                        "<label style='width: auto;margin-right: 8px;line-height: 35px'>添加样式</label>" +
                                        "<select style='flex: 1;height: 35px'><option disabled selected=\"selected\" value=\"\">请选择样式</option></select>" +
                                    "</div>"+
                                    "<div style='display: flex;align-items: center;margin-top: 10px'>"+
                                        "<label style='width: auto;margin-right: 8px;line-height: 35px'>样式参数</label>" +
                                        "<input type=\"text\" value=\"" + selection + "\" style='flex: 1;font-size: 13px;height: 35px;color: #404040' placeholder=\"请填写内容\" data-alt />" +
                                    "</div>"+
                                    "</div>";

                dialog = this.createDialog({
                    name   : dialogName,
                    title  : "添加HTML内联样式",
                    width  : 300,
                    height : 240,
                    mask   : settings.dialogShowMask,
                    drag   : settings.dialogDraggable,
                    content    : dialogHTML,
                    lockScreen : settings.dialogLockScreen,
                    maskStyle  : {
                        opacity         : settings.dialogMaskOpacity,
                        backgroundColor : settings.dialogMaskBgColor
                    },
                    buttons : {
                        enter  : [lang.buttons.enter, function() {

                            var css_val  = this.find("input").val();
                            var css_key   = this.find("select").val();

                            if (css_key === "")
                            {
								this.hide().lockScreen(false).hideMask();
								return false;
                            }

                            if (css_val === "")
                            {
								this.hide().lockScreen(false).hideMask();
                                return false;
                            }

                            cm.replaceSelection(css_key+":"+css_val);

                            this.hide().lockScreen(false).hideMask();

                            return false;
                        }],
                        cancel : [lang.buttons.cancel, function() {                                   
                            this.hide().lockScreen(false).hideMask();

                            return false;
                        }]
                    }
                });
            }

			var langSelect = dialog.find("select");//找到下拉框

			var input  = dialog.find("input");//html标签

			if (langSelect.find("option").length === 1) 
			{
				for (var key in codeLanguages)
				{
					var codeLang = codeLanguages[key];
					langSelect.append("<option value=\"" + key + "\" mode=\"" + codeLang[1] + "\">" + codeLang[0] + "</option>");
				}
			}

			langSelect.change(function(){
				var _mode = $(this).find("option:selected").attr("mode");
				input.val(_mode);
			});
		};

	};
    
	// CommonJS/Node.js
	if (typeof require === "function" && typeof exports === "object" && typeof module === "object")
    { 
        module.exports = factory;
    }
	else if (typeof define === "function")  // AMD/CMD/Sea.js
    {
		if (define.amd) { // for Require.js

			define(["editormd"], function(editormd) {
                factory(editormd);
            });

		} else { // for Sea.js
			define(function(require) {
                var editormd = require("./../../editormd");
                factory(editormd);
            });
		}
	} 
	else
	{
        factory(window.editormd);
	}

})();
