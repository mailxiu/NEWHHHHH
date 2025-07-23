/*!
 * Image (upload) dialog plugin for Editor.md
 *
 * @file        image-dialog.js
 * @author      pandao
 * @version     1.3.4
 * @updateTime  2015-06-09
 * {@link       https://github.com/pandao/editor.md}
 * @license     MIT
 */

(function() {

    var factory = function (exports) {

		var pluginName   = "html-dialog";

		exports.fn.htmlDialog = function() {

            var _this       = this;
            var cm          = this.cm;
            var lang        = this.lang;
            var editor      = this.editor;
            var settings    = this.settings;
            var cursor      = cm.getCursor();
            var selection   = cm.getSelection();
            var imageLang   = lang.dialog.image;
            var classPrefix = this.classPrefix;
            var iframeName  = classPrefix + "image-iframe";
			var dialogName  = classPrefix + pluginName, dialog;

			cm.focus();

            var loading = function(show) {
                var _loading = dialog.find("." + classPrefix + "dialog-mask");
                _loading[(show) ? "show" : "hide"]();
            };

            if (editor.find("." + dialogName).length < 1)
            {
                var guid   = (new Date).getTime();

                var dialogContent =  "<div class=\"editormd-form\" style='display: flex;flex-direction: column;justify-content: center;color: #999'>" +
                                        "<div style='display: flex;flex-direction: row;align-items: center;margin-bottom: 10px'>"+
                                            "<label style='width: auto;margin-right: 8px;line-height: 35px'>内容</label>" +
                                            "<input style='flex: 1;height: 35px' type=\"text\" value=\"" + selection + "\" placeholder=\"请填写内容\" data-alt />" +
                                        "</div>"+
                                        "<div style='width: 100%;display: flex;justify-content: space-between;flex-direction: row;margin-bottom: 10px'>"+
                                            "<div style='display: flex;height: 50px;flex-direction: row;align-items: center'>"+
                                                "<label style='width: auto;margin-right: 8px;line-height: 35px'>颜色</label>" +
                                                "<input type=\"color\" style='width: 45px;height: 35px' data-colour />" +
                                            "</div>"+
                                            "<div style='display: flex;height: 50px;flex-direction: row;align-items: center;'>"+
                                                "<label style='width: auto;margin-right: 8px;line-height: 35px'>大小</label>" +
                                                "<input type=\"number\" value=\"20\" style=\"width:65px;height: 35px;\" max=\"100\" data-size />" +
                                            "</div>"+
                                            "<div style='display: flex;height: 50px;flex-direction: row;align-items: center;'>"+
                                                "<label style='width: auto;margin-right: 8px;line-height: 35px;'>类型</label>" +
                                                "<select style='width: 45px;height: 35px'>" +
                                                    "<option selected=\"selected\" value=\"span\">行内</option>" +
                                                    "<option value=\"p\">块级</option>" +
                                                 "</select>" +
                                            "</div>"+
                                        "</div>"+
                                        "</div>";


                dialog = this.createDialog({
                    title      : "富文本",
                    width      : (settings.imageUpload) ? 465 : 380,
                    height     : 275,
                    name       : dialogName,
                    content    : dialogContent,
                    mask       : settings.dialogShowMask,
                    drag       : settings.dialogDraggable,
                    lockScreen : settings.dialogLockScreen,
                    maskStyle  : {
                        opacity         : settings.dialogMaskOpacity,
                        backgroundColor : settings.dialogMaskBgColor
                    },
                    buttons : {
                        enter : [lang.buttons.enter, function() {
                            var label = this.find("select").find("option:selected").val();//找到下拉框
                            var alt  = this.find("[data-alt]").val();//html标签
                            var colour = this.find("[data-colour]").val();//颜色
                            var size = this.find("[data-size]").val();//字体大小

                            if (alt === "")
                            {
                                alert("请填写内容");
                                return false;
                            }

                            if(label=='span'){
                                cm.replaceSelection("<span style=\"color: "+colour+";font-size:"+size+"px;\""+">"+alt+"</span>");
                            }else{
                                cm.replaceSelection("<p style=\"color: "+colour+";font-size:"+size+"px;\""+">"+alt+"</p>");
                            }


                            this.hide().lockScreen(false).hideMask();

                            //删除对话框
                            this.remove();

                            return false;
                        }],

                        cancel : [lang.buttons.cancel, function() {
                            this.hide().lockScreen(false).hideMask();

                            //删除对话框
                            this.remove();
                            
                            return false;
                        }]
                    }
                });

                dialog.attr("id", classPrefix + "image-dialog-" + guid);

				if (!settings.imageUpload) {
                    return ;
                }

				var fileInput  = dialog.find("[name=\"" + classPrefix + "image-file\"]");

				fileInput.bind("change", function() {
					var fileName  = fileInput.val();
					var isImage   = new RegExp("(\\.(" + settings.imageFormats.join("|") + "))$", "i"); // /(\.(webp|jpg|jpeg|gif|bmp|png))$/

					if (fileName === "")
					{
						alert(imageLang.uploadFileEmpty);

                        return false;
					}

                    if (!isImage.test(fileName))
					{
						alert(imageLang.formatNotAllowed + settings.imageFormats.join(", "));

                        return false;
					}

                    loading(true);

                    var submitHandler = function() {

                        var uploadIframe = document.getElementById(iframeName);

                        uploadIframe.onload = function() {

                            loading(false);

                            var body = (uploadIframe.contentWindow ? uploadIframe.contentWindow : uploadIframe.contentDocument).document.body;
                            var json = (body.innerText) ? body.innerText : ( (body.textContent) ? body.textContent : null);

                            json = (typeof JSON.parse !== "undefined") ? JSON.parse(json) : eval("(" + json + ")");

                            if(!settings.crossDomainUpload)
                            {
                              if (json.success === 1)
                              {
                                  dialog.find("[data-url]").val(json.url);
                              }
                              else
                              {
                                  alert(json.message);
                              }
                            }

                            return false;
                        };
                    };

                    dialog.find("[type=\"submit\"]").bind("click", submitHandler).trigger("click");
				});
            }

			dialog = editor.find("." + dialogName);
			dialog.find("[type=\"text\"]").val("");
			dialog.find("[type=\"file\"]").val("");
			dialog.find("[data-link]").val("http://");

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
