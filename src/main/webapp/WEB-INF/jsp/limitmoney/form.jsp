<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html  lang="en" class="no-js">

<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title> - 表单验证 jQuery Validation</title>
    <meta name="keywords" content="">
    <meta name="description" content="">
    <jsp:include page="/static/style.jsp"/>

    <script src="${home}/static/js/layui.js" charset="utf-8"></script>
    <script src="${home}/static/js/jquery-1.9.1.min.js" charset="utf-8"></script>
    <script src="${home}/static/js/jquery.validate.min.js" charset="utf-8"></script>


</head>
<style>
    .gray-bg{overflow-y: scroll !important;}
    .layui-form-item .layui-input-inline{
        width: 100px;!important;
    }
    .layui-form-item{margin-bottom: 0px!important;}
</style>
<body class="gray-bg">
<div class="wrapper wrapper-content animated fadeInRight">
    <div class="row">
        <div class="col-sm-12">
            <div class="ibox float-e-margins">
                <div class="ibox-content">
                    <fieldset class="layui-elem-field layui-field-title" style="margin-top: 20px;">
                        <legend>开奖号码及范围限注</legend>
                    </fieldset>
                    <form class="form-horizontal m-t" id="frm" method="post"    >
                        <input type="hidden" id="id" name="id" value="${limitMoney.id}">
                        <div class="layui-form-item">
                        <div class="layui-inline">
                            <label class="layui-form-label">0</label>
                            <div class="layui-input-inline">
                                <input type="text" name="m0" id="m0" autocomplete="off" class="layui-input"   value="${limitMoney.m0}">
                            </div>
                        </div>
                        <div class="layui-inline">
                            <label class="layui-form-label">小</label>
                            <div class="layui-input-inline">
                                <input type="text" name="m112" id="m112" autocomplete="off" class="layui-input"   value="${limitMoney.m112}">
                            </div>
                        </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">大</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1324" id="m1324" autocomplete="off" class="layui-input" value="${limitMoney.m1324}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">单</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="danhao" id="danhao" autocomplete="off" class="layui-input"   value="${limitMoney.danhao}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">双</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="shuanghao" id="shuanghao" autocomplete="off" class="layui-input"   value="${limitMoney.shuanghao}">
                                </div>
                            </div>

                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">1-8</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m018" id="m018" autocomplete="off" class="layui-input"   value="${limitMoney.m018}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">9-16</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m916" id="m916" autocomplete="off" class="layui-input"   value="${limitMoney.m916}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">17-24</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1724" id="m1724" autocomplete="off" class="layui-input"   value="${limitMoney.m1724}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">1-6</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m016" id="m016" autocomplete="off" class="layui-input"   value="${limitMoney.m016}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">7-12</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m712" id="m712" autocomplete="off" class="layui-input"   value="${limitMoney.m712}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">13-18</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1318"  autocomplete="off" class="layui-input"   value="${limitMoney.m1318}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">19-24</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1924"  autocomplete="off" class="layui-input"   value="${limitMoney.m1924}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">1-3</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m013" id="m013" autocomplete="off" class="layui-input"   value="${limitMoney.m013}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">7-9</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m79" id="m79" autocomplete="off" class="layui-input"   value="${limitMoney.m79}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">13-15</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1315"  autocomplete="off" class="layui-input"   value="${limitMoney.m1315}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">19-21</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1921"  autocomplete="off" class="layui-input"   value="${limitMoney.m1921}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">4-6</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m46" id="m46" autocomplete="off" class="layui-input"   value="${limitMoney.m46}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">10-12</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1012" id="m1012" autocomplete="off" class="layui-input"   value="${limitMoney.m1012}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">16-18</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1618"  autocomplete="off" class="layui-input"   value="${limitMoney.m1618}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">22-24</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m2224"  autocomplete="off" class="layui-input"   value="${limitMoney.m2224}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">1</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m1" id="m1" autocomplete="off" class="layui-input"   value="${limitMoney.m1}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">7</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m7" id="m7" autocomplete="off" class="layui-input" value="${limitMoney.m7}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">13</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m13" id="m13" autocomplete="off" class="layui-input" value="${limitMoney.m13}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">19</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m19" id="m19" autocomplete="off" class="layui-input" value="${limitMoney.m19}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">2</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m2" id="m2" autocomplete="off" class="layui-input" value="${limitMoney.m2}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">8</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m8" id="m8" autocomplete="off" class="layui-input" value="${limitMoney.m8}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">14</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m14" id="m14" autocomplete="off" class="layui-input" value="${limitMoney.m14}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">20</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m20" id="m20" autocomplete="off" class="layui-input" value="${limitMoney.m20}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">3</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m3" id="m3" autocomplete="off" class="layui-input" value="${limitMoney.m3}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">9</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m9" id="m9" autocomplete="off" class="layui-input" value="${limitMoney.m9}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">15</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m15" id="m15" autocomplete="off" class="layui-input" value="${limitMoney.m15}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">21</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m21" id="m21" autocomplete="off" class="layui-input" value="${limitMoney.m21}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">4</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m4" id="m4" autocomplete="off" class="layui-input" value="${limitMoney.m4}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">10</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m10" id="m10" autocomplete="off" class="layui-input" value="${limitMoney.m10}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">16</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m16" id="m16" autocomplete="off" class="layui-input" value="${limitMoney.m16}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">22</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m22" id="m22" autocomplete="off" class="layui-input" value="${limitMoney.m22}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">5</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m5" id="m5" autocomplete="off" class="layui-input" value="${limitMoney.m5}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">11</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m11" id="m11" autocomplete="off" class="layui-input" value="${limitMoney.m11}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">17</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m17" id="m17" autocomplete="off" class="layui-input" value="${limitMoney.m17}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">23</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m23" id="m23" autocomplete="off" class="layui-input" value="${limitMoney.m23}">
                                </div>
                            </div>
                        </div>
                        <div class="layui-form-item">
                            <div class="layui-inline">
                                <label class="layui-form-label">6</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m6" id="m6" autocomplete="off" class="layui-input" value="${limitMoney.m6}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">12</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m12" id="m12" autocomplete="off" class="layui-input" value="${limitMoney.m12}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">18</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m18" id="m18" autocomplete="off" class="layui-input" value="${limitMoney.m18}">
                                </div>
                            </div>
                            <div class="layui-inline">
                                <label class="layui-form-label">24</label>
                                <div class="layui-input-inline">
                                    <input type="text" name="m24" id="m24" autocomplete="off" class="layui-input" value="${limitMoney.m24}">
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <div style="margin: 0 auto !important;width: 190px">
                                <button class="btn layui-btn layui-btn-lg  layui-btn-normal" type="submit">提交</button>
                                <button class="btn layui-btn layui-btn-lg  layui-btn" type="button" onclick="closeW()">关闭</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

</div>
<script type="text/javascript">
    $(document).ready(function () {
        $("#frm").validate({
            rules: {
                tKey: {
                    required: true,
                    minlength: 1,
                    maxlength: 20
                },
                tValue: {
                    required: true,
                    minlength: 1,
                    maxlength: 20
                }
            },
            messages: {
                tKey:{
                    required:"键不能为空",
                    minlength:'最小长度为1',
                    maxlength:'最大长度为20',
                },
                tValue:{
                    required:"值不能为空",
                    minlength:'最小长度为1',
                    maxlength:'最大长度为20',
                }
            },
            submitHandler: function (form) {
                $.ajax({
                    type: "POST",
                    dataType: "json",
                    url: "${home}/limitMoney/edit",
                    data: $(form).serialize(),
                    success: function (result) {
                        layer.msg(result.msg, {time: 2000}, function () {
                            var index = parent.layer.getFrameIndex(window.name); //先得到当前iframe层的索引
                            if (result.code==200) {
                                parent.layer.close(index);
                            }/*else {
                                parent.layer.msg(result.msg);
                            }*/
                        });
                    }
                });
            }
        });
    });
    function closeW(){
        var index = parent.layer.getFrameIndex(window.name); //先得到当前iframe层的索
        parent.layer.close(index);
    }
</script>

</body>
<style>
    .row{margin: 0 !important;overflow: hidden}
    .layui-form-label{width: 70px !important;}

</style>
</html>
