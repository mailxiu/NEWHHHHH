/*!
 * Goto line dialog plugin for Editor.md
 *
 * @file        goto-line-dialog.js
 * @author      pandao
 * @version     1.2.1
 * @updateTime  2015-06-09
 * {@link       https://github.com/pandao/editor.md}
 * @license     MIT
 */

(function() {

	var factory = function (exports) {

		var $            = jQuery;
		var pluginName   = "color-dialog";

		var langs = {
			"zh-cn" : {
				toolbar : {
					"goto-line" : "跳转到行"
				},
				dialog : {
					"goto-line" : {
						title  : "跳转到行",
						label  : "选择颜色",
						error  : "错误："
					}
				}
			},
			"zh-tw" : {
				toolbar : {
					"goto-line" : "跳轉到行"
				},
				dialog : {
					"goto-line" : {
						title  : "跳轉到行",
						label  : "請輸入行號",
						error  : "錯誤："
					}
				}
			},
			"en" : {
				toolbar : {
					"goto-line" : "Goto line"
				},
				dialog : {
					"goto-line" : {
						title  : "Goto line",
						label  : "Enter a line number, range ",
						error  : "Error: "
					}
				}
			}
		};

		exports.fn.colorDialog = function() {
			var _this       = this;
			var cm          = this.cm;
			var editor      = this.editor;
			var settings    = this.settings;
			var path        = settings.pluginPath + pluginName +"/";
			var classPrefix = this.classPrefix;
			var dialogName  = classPrefix + pluginName, dialog;

			$.extend(true, this.lang, langs[this.lang.name]);
			this.setToolbar();

			var lang        = this.lang;
			var dialogLang  = lang.dialog["goto-line"];
			var lineCount   = cm.lineCount();

			dialogLang.error += dialogLang.label + " 1-" + lineCount;

			if (editor.find("." + dialogName).length < 1) 
			{			
				var dialogContent = [
					"<div style=\"padding: 10px 0;display: flex;justify-content: center;align-items: center\">",
					"<input type=\"color\" style=\"width:75px;height: 75px;\" data-color />",
					"</div>"
				].join("\n");

				dialog = this.createDialog({
					name       : dialogName,
					title      : "替换颜色",
					width      : 200,
					height     : 230,
					mask       : settings.dialogShowMask,
					drag       : settings.dialogDraggable,
					content    : dialogContent,
					lockScreen : settings.dialogLockScreen,
					maskStyle  : {
						opacity         : settings.dialogMaskOpacity,
						backgroundColor : settings.dialogMaskBgColor
					},
					buttons    : {
                        enter : [lang.buttons.enter, function() {
							var color   = this.find("[data-color]").val();

							_this.replaceSelection(color);

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

			dialog = editor.find("." + dialogName);

			this.dialogShowMask(dialog);
			this.dialogLockScreen();
			dialog.show();
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
