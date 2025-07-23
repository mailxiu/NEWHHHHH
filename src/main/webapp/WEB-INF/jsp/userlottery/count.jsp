<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js" style="height: 100%;min-height: 1080px;width: 100%;min-width: 720px;">


<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title>用户管理页面</title>
    <jsp:include page="/static/style.jsp"/>
    <link rel="stylesheet" href="${home}/static/css/bootstrap-select.css" media="all">
</head>

<body class="gray-bg">
<div class="wrapper wrapper-content  animated fadeInRight">
    <div class="row">
        <div class="col-sm-12">
            <div class="ibox ">
                <div class="ibox-content">
                    <div class="row row-lg">
                        <div class="col-sm-12">
                            <!-- Example Card View -->
                            <div class="example-wrap">
                                <div class="demoTable" style="margin-left: 50px;">
                                    <%--<div class="layui-inline">--%>
                                    <%--<input class="layui-input" name="" id="categoryCode" autocomplete="off"--%>
                                    <%--placeholder="字典目录编码">--%>
                                    <%--</div>--%>
                                    <%--<div class="layui-inline">--%>
                                    <%--<input class="layui-input" name="" id="categoryValue" autocomplete="off"--%>
                                    <%--placeholder="字典项值">--%>
                                    <%--</div>--%>

                                    <div class="layui-input-inline" style="margin-top: 10px;display: none">
                                        <label>时间选择</label>
                                        <div class="layui-input-inline">

                                            <input type="text" id="date" placeholder="请选择时间" autocomplete="off"
                                                   class="layui-input">
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px;display: none">
                                        <label>是否管理员</label>
                                        <div class="layui-input-inline ">
                                            <select class="selectpicker " data-width="100px"  id="isAdmin">
                                                <option value="">全部用户</option>
                                                <option value="0">客户</option>
                                                <option value="1">管理员</option>
                                            </select>
                                        </div>

                                    </div>
                                        <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px;display: none">
                                            <label>是否中</label>
                                            <div class="layui-input-inline ">
                                                <select class="selectpicker " data-width="100px"  id="isLottery">
                                                    <option value="">全部</option>
                                                    <option value="1">中</option>
                                                    <option value="0">不中</option>
                                                </select>
                                            </div>

                                        </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px">
                                        <label>按用户</label>
                                        <div class="layui-input-inline ">


                                            <select class="selectpicker " data-live-search-placeholder="请输入" multiple
                                                    data-live-search="true" id="user" title="请选择用户"
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="5">

                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px;">
                                        <label>版号</label>
                                        <div class="layui-input-inline ">
                                            <select class="selectpicker" data-live-search-placeholder="请输入" multiple
                                                    data-live-search="true" id="banhao" title="请选择版号"
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="5">

                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px;display: none">
                                        <label>局号</label>
                                        <div class="layui-input-inline ">


                                            <select class="selectpicker" data-live-search-placeholder="请输入" multiple
                                                    data-live-search="true" title="请选择局号"
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="10" id="juhao">

                                            </select>
                                        </div>

                                    </div>
                                        <div class="layui-input-inline" style="margin-left: 10px;margin-top: 10px">

                                            <button class="layui-btn  layui-btn-normal" data-type="reload">查询</button>
                                            <button class="layui-btn  layui-btn" onclick="reset()">重置</button>
                                        </div>
                                </div>
                                <div class="example">
                                    <table class="layui-hide" lay-filter="mainTable" id="table"></table>
                                </div>
                            </div>
                            <!-- End Example Card View -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<script src="${home}/static/js/layui.js" charset="utf-8"></script>
<script src="${home}/static/js/jquery-1.9.1.min.js" charset="utf-8"></script>
<script src="${home}/static/js/popper.min.js"></script>
<script src="${home}/static/js/bootstrap.js"></script>
<%--<script src="${home}/static/js/bootstrap-dropdown.js"></script>--%>
<script src="${home}/static/js/bootstrap-select.js"></script>
<script src="${home}/static/js/defaults-zh_CN.min.js"></script>
<script>
    let usernameStr = '${username}'
    $(document).ready(function () {
        //初始化表格,动态从服务器加载数据

        layui.use('table', function () {
            var table = layui.table;
            table.render({
                elem: '#table'
                , url: '${home}/userLottery/countList'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                , id: 'table'
                , height: 'full-100'
                , autoSort: false
                , where: {sortName: 'createDate', sortOrder: 'desc',username:usernameStr}
                , toolbar: '#toolbarDemo'
                , defaultToolbar: ['filter']
                , align: 'center'
                , cols: [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '账号',
                        field: 'username',
                        align: 'center'
                    }, {
                        title: '昵称',
                        field: 'userNickName',
                        align: 'center'
                    }, {
                        title: '版号',
                        field: 'banhao',
                        align: 'center'
                    }, {
                        title: "下注号码",
                        field: "lotteryTotalBtn",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "号码次数",
                        field: "count",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }


                ]]
                , parseData: function (res) { //res 即为原始返回的数据
                    return {
                        "code": 0, //解析接口状态
                        "data": res.records, //解析数据列表
                        "count": res.total,

                    };
                }
                , page: true
                , limits: [5, 10, 15, 20, 50, 100]
                , limit: 10 //每页默认显示的数量
            });

            //排序重载
            table.on('sort(mainTable)', function (obj) {
                table.reload('table', {initSort: obj, where: {sortName: obj.field, sortOrder: obj.type}});
            });

            var $ = layui.$, active = {
                reload: function () {
                    var date = $('#date');
                    var user = $('#user').val();
                    var banhao = $('#banhao').val();
                    var juhao = $('#juhao').val()
                    let username = '';
                    let isAdmin = $('#isAdmin').val()
                    let isLottery = $('#isLottery').val()

                    if (user) {
                        username = user.join(',');
                    }
                    if (banhao) {
                        banhao = banhao.join(',')
                    }
                    if (juhao) {
                        juhao = juhao.join(',')
                    }
                    if(usernameStr){
                        username = usernameStr;
                    }
                    table.reload('table', {
                        page: {
                            curr: 1 //重新从第 1 页开始
                        }
                        , where: {
                            dateStr: date.val(),
                            username: username,
                            banhao, juhao,isAdmin,isLottery
                        }
                    }, 'data');
                }
            };

            $('.demoTable .layui-btn').on('click', function () {
                var type = $(this).data('type');
                active[type] ? active[type].call(this) : '';
            });


        });
        layui.use('laydate', function () {
            var laydate = layui.laydate;
            laydate.render({
                elem: '#date'
                , type: 'date'
                , range: '~'
                , format: 'yyyy-MM-dd'
            });
        })
        let user = $('#user');
        let banhao = $('#banhao');
        let juhao = $('#juhao')

        function getUserList() {
            let isAdmin = $('#isAdmin').val();
            $(user).html('');
            $(user).selectpicker('refresh');
            $.ajax({
                type: "POST",
                dataType: "json",
                url: "${home}/comment/getUserList",
                data: {isAdmin},
                success: function (result) {
                    console.log(result)
                    if (result.length > 0) {
                        for (let i = 0; i < result.length; i++) {
                            let option = '<option  value="' + result[i].value + '">' + result[i].name + '</option>';
                            $(user).append(option)
                            /* $(user).append('<option data-divider="true"></option>')*/
                        }
                    }
                    $(user).selectpicker('refresh');
                    if(usernameStr){
                        $('#user').selectpicker('val',usernameStr);
                    }

                }
            });
        }

        function getBanHaoList() {
            let username = $('#user').val();
            if(username){
                username = username.join(',')
            }
            if(usernameStr){
                username = usernameStr;
            }
            $('#banhao').html('');
            $('#banhao').selectpicker('refresh');
            $.ajax({
                type: "POST",
                dataType: "json",
                url: "${home}/comment/getBanHaoList",
                data: {username},
                success: function (result) {
                    if (result.length > 0) {
                        for (let i = 0; i < result.length; i++) {
                            let option = '<option  value="' + result[i].value + '">第' + result[i].name + '版</option>';
                            $(banhao).append(option)
                            /* $(user).append('<option data-divider="true"></option>')*/
                        }
                    }

                    $(banhao).selectpicker('refresh');


                }
            });
        }

        function getJuHaoList() {
            $.ajax({
                type: "POST",
                dataType: "json",
                url: "${home}/comment/getJuHaoList",
                data: {},
                success: function (result) {
                    if (result.length > 0) {
                        for (let i = 0; i < result.length; i++) {
                            let option = '<option  value="' + result[i].value + '">第' + result[i].name + '局</option>';
                            $(juhao).append(option)
                            /* $(user).append('<option data-divider="true"></option>')*/
                        }
                    }
                    $(juhao).selectpicker('refresh');
                    $(juhao).selectpicker('render');
                }
            });
        }

        getUserList();
        getBanHaoList();
        getJuHaoList();
        $('#isAdmin').on('hidden.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            getUserList()
        });
        $('#user').on('hidden.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            getBanHaoList()
        });
        if(usernameStr){
            $('#isAdmin').prop('disabled', true);
            $('#user').prop('disabled', true);
        }

    });

    function reset() {
       $('#date').val('');
       if(!usernameStr){
           $('#isAdmin').selectpicker('val','');
           $('#user').selectpicker('val','');
       }

        $('#banhao').selectpicker('val','');
        $('#juhao').selectpicker('val','');

    }

    function tableReload() {
        layui.use('table', function () {
            var table = layui.table;
            table.reload('table');
        })
    }
    $.fn.modal.Constructor.prototype.enforceFocus = function () {};
</script>
<script type="text/html" id="toolbarDemo">
    <span>用户投注表</span>
</script>

</body>
<style>
    .dropdown-menu > .active > a {
        background-color: #4f93fe !important;
    }

    .selected > a {
        background-color: #4f93fe !important;
        color: white !important;
    }

    .bootstrap-select {
        width: 165px !important;
    }

    .isAdmin {
        width: 100px;
    }
    .actions-btn{
        width: 46% !important;
        margin-left: 5px !important;
    }
</style>
</html>
