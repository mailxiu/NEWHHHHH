<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en" class="no-js" style="height: 100%;min-height: 1080px;width: 100%;min-width: 720px;">

<style>
    html{
        overflow-y: auto !important;
    }
</style>
<head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">


    <title>用户管理页面</title>
    <jsp:include page="/static/style.jsp"/>
    <link rel="stylesheet" href="${home}/static/css/bootstrap-select.css" media="all">
</head>

<body class="gray-bg">
<div id="mulu" class="layui-layer-content" style="display: none">
    <ul class="site-dir layui-layer-wrap">
        <li><a href="#userTable"><cite>用户统计表</cite></a></li>
        <li><a href="#shangxiaTable"><cite>用户上下分统计表</cite></a></li>
    </ul>
</div>
<div class="wrapper wrapper-content  animated fadeInRight">
    <div class="row">
        <div class="col-sm-12">
            <div class="ibox ">
                <div class="ibox-content">
                    <div class="row row-lg">
                        <label style="margin-left: 50px" id="userTable">用户投注统计表</label>
                        <hr class="layui-border-blue" />
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

                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 5px">
                                        <label>时间类型</label>
                                        <div class="layui-input-inline ">
                                            <select class="selectpicker " data-width="100px" id="dateType" value = '3'>
                                                <option value="1">今天</option>
                                                <option value="2">近7天</option>
                                                <option value="3" selected>自定义</option>
                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-top: 5px">
                                        <label>时间选择</label>
                                        <div class="layui-input-inline">

                                            <input type="text" id="date" placeholder="请选择时间" autocomplete="off"
                                                   class="layui-input">
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 5px">
                                        <label>是否管理员</label>
                                        <div class="layui-input-inline ">
                                            <select class="selectpicker " data-width="100px" id="isAdmin">
                                                <option value="">全部用户</option>
                                                <option value="0">客户</option>
                                                <option value="1">管理员</option>
                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 5px">
                                        <label>按用户</label>
                                        <div class="layui-input-inline ">


                                            <select class="selectpicker " data-live-search-placeholder="请输入" multiple
                                                    data-live-search="true" id="user" title="请选择用户"
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="5">

                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 0px">
                                        <label>版号</label>
                                        <div class="layui-input-inline ">
                                            <select class="selectpicker" data-live-search-placeholder="请输入" multiple
                                                    data-live-search="true" id="banhao" title="请选择版号"
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="5">

                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 0px">
                                        <label>局号</label>
                                        <div class="layui-input-inline ">


                                            <select class="selectpicker" data-live-search-placeholder="请输入" multiple
                                                    data-live-search="true" title="请选择局号"
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="10" id="juhao">

                                            </select>
                                        </div>

                                    </div>

                                </div>
                                <fieldset class="layui-elem-field layui-field-title"
                                          style="margin: 5px 0px 0px 0px !important;">
                                </fieldset>
                                <div class="demoTable" style="margin-left: 50px;">

                                    <div class="layui-input-inline" style="margin-top: 0px;margin-left: 10px">
                                        <label>统计类型</label>
                                        <div class="layui-input-inline ">


                                            <select class="selectpicker " data-live-search-placeholder="请输入"
                                                    data-live-search="false" id="countType" title="请选择类型" value="1"
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="5">
                                                <option value="1" selected>按局号统计</option>
                                                <option value="2">按版号统计</option>
                                                <option value="3">按时间统计</option>
                                                <option value="4">按用户统计</option>
                                                <option value="5">按版/用户统计</option>
                                                <option value="6">按版/用户/局统计</option>
                                                <option value="7">按时间/用户统计</option>

                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 0px">
                                        <label>统计局数</label>
                                        <div class="layui-input-inline ">


                                            <select class="selectpicker " data-live-search-placeholder="请输入"
                                                    data-live-search="false" id="countJu" title="请选择类型" value='1'
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="5">
                                                <option value="1" selected>前20局</option>
                                                <option value="2">后20局</option>
                                                <option value="3" >40局</option>
                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 5px">

                                        <button class="layui-btn  layui-btn-normal" data-type="reload" id="reload">查询</button>
                                        <button class="layui-btn2 layui-btn  layui-btn-normal" onclick="exportFile()">导出</button>
                                        <button class="layui-btn  layui-btn" onclick="reset()">重置</button>
                                    </div>
                                </div>
                                <div class="example">
                                    <table class="layui-hide" lay-filter="mainTable" id="table"></table>
                                </div>
                            </div>
                            <!-- End Example Card View -->
                        </div>
                        <label style="margin-left: 50px" id="shangxiaTable">用户上下分统计表</label>
                        <hr class="layui-border-blue" />
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

                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 5px">
                                        <label>时间类型</label>
                                        <div class="layui-input-inline ">
                                            <select class="selectpicker " data-width="100px" id="dateType2" value = '3'>
                                                <option value="1">今天</option>
                                                <option value="2">近7天</option>
                                                <option value="3" selected>自定义</option>
                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-top: 5px;width: 380px">
                                        <label>时间选择</label>
                                        <div class="layui-input-inline" style="width: 315px;">

                                            <input type="text" id="date2" placeholder="请选择时间" autocomplete="off"
                                                   class="layui-input">
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 5px">
                                        <label>是否管理员</label>
                                        <div class="layui-input-inline ">
                                            <select class="selectpicker " data-width="100px" id="isAdmin2">
                                                <option value="">全部用户</option>
                                                <option value="0">客户</option>
                                                <option value="1">管理员</option>
                                            </select>
                                        </div>

                                    </div>
                                    <div class="layui-input-inline" style="margin-left: 10px;margin-top: 5px">
                                        <label>按用户</label>
                                        <div class="layui-input-inline ">


                                            <select class="selectpicker " data-live-search-placeholder="请输入" multiple
                                                    data-live-search="true" id="user2" title="请选择用户"
                                                    data-divider="true"
                                                    data-actions-box="true" data-size="5">

                                            </select>
                                        </div>

                                    </div>
                                        <div class="layui-input-inline" style="margin-top: 0px">
                                            <label>统计类型</label>
                                            <div class="layui-input-inline ">


                                                <select class="selectpicker " data-live-search-placeholder="请输入"
                                                        data-live-search="false" id="countType2" title="请选择类型" value="1"
                                                        data-divider="true"
                                                        data-actions-box="true" data-size="5">
                                                    <option value="1" selected>按时间统计</option>
                                                    <option value="2">按用户统计</option>
                                                    <option value="3">按时间/用户统计</option>
                                                </select>
                                            </div>

                                        </div>

                                        <div class="layui-input-inline" style="margin-left: 10px;margin-top: 5px">

                                            <button class="layui-btn2 layui-btn  layui-btn-normal" data-type="reload2">查询</button>
                                            <button class="layui-btn2 layui-btn  layui-btn-normal" onclick="exportFile2()">导出</button>
                                            <button class="layui-btn  layui-btn" onclick="reset2()">重置</button>
                                        </div>
                                </div>

                                <div class="example">
                                    <table class="layui-hide" lay-filter="mainTable2" id="table2"></table>
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
    var cols = [[ //标题栏
        /*{type: 'radio', fixed: 'left'},*/
        {
            field: 'id',
            title: 'ID',
            width: 80,
            hide: true
            /*sort: true*/
        }, {
            title: '版号',
            field: 'banhao',
            align: 'center',
            totalRowText: '小计'
        }, {
            title: "局号",
            field: "qihao",
            align: 'center'
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }, {
            title: "开奖号码",
            field: "lotteryNum",
            align: 'center'
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }
        , {
            title: "总下注积分",
            field: "xiaMoney",
            align: 'center',
            totalRowText: '总收入',
            totalRow: true
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }
        , {
            title: "总中奖积分",
            field: "lotteryMoney",
            align: 'center',
            totalRowText: '总支出',
            totalRow: true
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }, {
            title: "总盈亏",
            field: "profitLoss",
            align: 'center',
            totalRowText: '总盈亏',
            totalRow: true,
            templet: function (d) {
                if (d.profitLoss < 0) {
                    return '<span style="color: red">' + d.profitLoss + '</span>'
                } else {
                    return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                }

                return d.profitLoss

            }
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }
    ]]
    var cols2 = [[ //标题栏
        /*{type: 'radio', fixed: 'left'},*/
        {
            field: 'id',
            title: 'ID',
            width: 80,
            hide: true
            /*sort: true*/
        }, {
            title: '操作日期',
            field: 'createDate',
            align: 'center',
            totalRowText: '小计',
            templet: function (d) {
                return '<span>' + d.createDate.substring(0,10) + '</span>'
            }
        }
        , {
            title: "总上分积分",
            field: "xiaMoney",
            align: 'center',
            totalRowText: '总收入',
            totalRow: true
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }
        , {
            title: "总下分积分",
            field: "lotteryMoney",
            align: 'center',
            totalRowText: '总支出',
            totalRow: true
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }, {
            title: "总赠送积分",
            field: "sumGiveMoney",
            align: 'center',
            totalRowText: '总赠送积分',
            totalRow: true
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }, {
            title: "总盈亏",
            field: "profitLoss",
            align: 'center',
            totalRowText: '总盈亏',
            totalRow: true,
            templet: function (d) {
                if (d.profitLoss < 0) {
                    return '<span style="color: red">' + d.profitLoss + '</span>'
                } else {
                    return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                }

                return d.profitLoss

            }
            /*sort: true*/
            /* , templet: function (d) {
                 return '<span>' + crtTimeFtt(d.createTime) + '</span>'
             }*/
        }
    ]]
    $(document).ready(function () {
        //初始化表格,动态从服务器加载数据
        let countType = $("#countType").val()
        let countType2 = $("#countType2").val()
        let countJu = $("#countJu").val();

        layui.use('table', function () {
            var table = layui.table;
            table.render({
                elem: '#table'
                , url: '${home}/userLottery/listSum'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                , id: 'table'
                , height: 'full-300'
                , autoSort: false
                , where: {sortName: 'createDate', sortOrder: 'desc', countType, countJu}
                , toolbar: '#toolbarDemo'
                , defaultToolbar: ['filter']
                , align: 'center'
                , totalRow: true
                , cols: cols
                , parseData: function (res) { //res 即为原始返回的数据
                    return {
                        "code": 0, //解析接口状态
                        "data": res.records, //解析数据列表
                        "count": res.total,
                        totalRow: res.totalRow

                    };
                },
                done: function (res, curr, count) {
                    let tds = $('.layui-table-total').find('td');
                    $(tds).each(function (index) {
                        let text = $(this).text();
                        let field = $(this).data('field');
                        if (field == 'profitLoss') {
                            if (text < 0) {
                                $(this).find('div').css('color', 'red')
                            } else {
                                $(this).find('div').css('color', '#4f93fe')
                            }
                        }
                    });


                }
                , page: true
                , limits: [10, 20, 40, 60, 100]
                , limit: 20 //每页默认显示的数量
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
                    if (user) {
                        username = user.join(',');
                    }
                    if (banhao) {
                        banhao = banhao.join(',')
                    }
                    if (juhao) {
                        juhao = juhao.join(',')
                    }
                    let countType = $("#countType").val()
                    let countJu = $("#countJu").val();
                    let dateType = $('#dateType').val();
                    table.reload('table', {
                        page: {
                            curr: 1 //重新从第 1 页开始
                        }
                        , where: {
                            dateStr: date.val(),
                            username: username,
                            banhao, juhao, isAdmin, countType, countJu
                        },cols:cols
                    }, 'data');
                }
            };

            $('.demoTable .layui-btn').on('click', function () {
                var type = $(this).data('type');
                active[type] ? active[type].call(this) : '';
            });


        });
        layui.use('table', function () {
            var table2 = layui.table;
            table2.render({
                elem: '#table2'
                , url: '${home}/recharge/listSum'
                , request: {
                    pageName: 'pageNumber' //页码的参数名称，默认：page
                    , limitName: 'pageSize' //每页数据量的参数名，默认：limit
                }
                , id: 'table2'
                , height: 'full-100'
                , autoSort: false
                , where: {sortName: 'createDate', sortOrder: 'desc', countType:countType2}
                , toolbar: '#toolbarDemo2'
                , defaultToolbar: ['filter']
                , align: 'center'
                , totalRow: true
                , cols: cols2
                , parseData: function (res) { //res 即为原始返回的数据
                    return {
                        "code": 0, //解析接口状态
                        "data": res.records, //解析数据列表
                        "count": res.total,
                        totalRow: res.totalRow

                    };
                },
                done: function (res, curr, count) {
                    let tds = $('.layui-table-total').find('td');
                    $(tds).each(function (index) {
                        let text = $(this).text();
                        let field = $(this).data('field');
                        if (field == 'profitLoss') {
                            if (text < 0) {
                                $(this).find('div').css('color', 'red')
                            } else {
                                $(this).find('div').css('color', '#4f93fe')
                            }
                        }
                    });


                }
                , page: true
                , limits: [10, 20, 40, 60, 100]
                , limit: 20 //每页默认显示的数量
            });


            var $ = layui.$, active2 = {
                reload2: function () {
                    var date = $('#date2');
                    var user = $('#user2').val();

                    let username = '';
                    let isAdmin = $('#isAdmin2').val()
                    if (user) {
                        username = user.join(',');
                    }
                    let countType = $("#countType2").val()
                    let dateType = $('#dateType2').val();
                    table2.reload('table2', {
                        page: {
                            curr: 1 //重新从第 1 页开始
                        }
                        , where: {
                            dateStr: date.val(),
                            username: username,
                           isAdmin, countType
                        },cols:cols2
                    }, 'data');
                }
            };

            $('.layui-btn2').on('click', function () {
                var type = $(this).data('type');
                active2[type] ? active2[type].call(this) : '';
            });


        });
        layui.use('laydate', function () {
            var laydate = layui.laydate;
            laydate.render({
                elem: '#date'
                , type: 'datetime'
                , range: '~'
                , format: 'yyyy-MM-dd'
            });
        })
        layui.use('laydate', function () {
            var laydate = layui.laydate;
            laydate.render({
                elem: '#date2'
                , type: 'datetime'
                , range: '~'
                /*, format: 'yyyy-MM-dd hh:'*/
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


                }
            });
        }
        function getUserList2() {
            let isAdmin = $('#isAdmin2').val();
            $('#user2').html('');
            $('#user2').selectpicker('refresh');
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
                            $('#user2').append(option)
                            /* $(user).append('<option data-divider="true"></option>')*/
                        }
                    }
                    $('#user2').selectpicker('refresh');


                }
            });
        }

        function getBanHaoList() {
            let username = $('#user').val();
            if (username) {
                username = username.join(',')
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
                            if(i==0){
                                let option = '<option  value="' + result[i].value + '" selected>第' + result[i].name + '版</option>';
                                $(banhao).append(option)
                            }else {
                                let option = '<option  value="' + result[i].value + '">第' + result[i].name + '版</option>';
                                $(banhao).append(option)
                            }

                            /* $(user).append('<option data-divider="true"></option>')*/
                        }
                    }

                    $(banhao).selectpicker('refresh');
                   $('#reload').click();


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
        getUserList2();
        getBanHaoList();
        getJuHaoList();

        $('#isAdmin').on('changed.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            getUserList()
        });
        $('#isAdmin2').on('changed.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            getUserList2()
        });
        $('#user').on('changed.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            getBanHaoList()
        });
        $('#countType').on('changed.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            if(clickedIndex==1){
                cols = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '版号',
                        field: 'banhao',
                        align: 'center',
                        totalRowText: '小计'
                    }, {
                        title: "局号",
                        field: "qihao",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "开奖号码",
                        field: "lotteryNum",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总下注积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总中奖积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if(clickedIndex==2){
                cols = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '版号',
                        field: 'banhao',
                        align: 'center',
                        totalRowText: '小计'
                    }
                    , {
                        title: "总下注积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总中奖积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if (clickedIndex==3){
                cols = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '开奖日期',
                        field: 'createDate',
                        align: 'center',
                        totalRowText: '小计',
                         templet: function (d) {
                            return '<span>' + d.createDate.substring(0,10) + '</span>'
                        }
                    }
                    , {
                        title: "总下注积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总中奖积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if(clickedIndex==4){
                cols = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '用户账号',
                        field: 'username',
                        align: 'center',
                        totalRowText: '小计'
                    }, {
                        title: "用户昵称",
                        field: "userNickName",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总下注积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总中奖积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if(clickedIndex==5){
                cols = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '版号',
                        field: 'banhao',
                        align: 'center',
                        totalRowText: '小计'
                    }, {
                        title: "用户账号",
                        field: "username",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "用户昵称",
                        field: "userNickName",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总下注积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总中奖积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if(clickedIndex==6){
                cols = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '版号',
                        field: 'banhao',
                        align: 'center',
                        totalRowText: '小计'
                    }, {
                        title: "局号",
                        field: "qihao",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "用户账号",
                        field: "username",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "用户昵称",
                        field: "userNickName",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "开奖号码",
                        field: "lotteryNum",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总下注积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总中奖积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if(clickedIndex==7){
                cols = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '下注时期',
                        field: 'createDate',
                        align: 'center',
                        totalRowText: '小计'
                    }, {
                        title: "用户账号",
                        field: "username",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "用户昵称",
                        field: "userNickName",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "开奖号码",
                        field: "lotteryNum",
                        align: 'center'
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总下注积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总中奖积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if(clickedIndex!=1&&clickedIndex!=6){
                $('#countJu').selectpicker('val',3);
                $('#countJu').prop('disabled', true);
                $('#countJu').selectpicker('refresh');
            }else {
                $('#countJu').prop('disabled', false);
                $('#countJu').selectpicker('refresh');
            }
        });
        $('#dateType').on('changed.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            layui.use('util', function(){
                var util = layui.util;
                let format = 'yyyy-MM-dd'
                //示例
                if(clickedIndex==2){
                    $('#date').prop('disabled', false);

                }else {
                    /*$('#date').prop('disabled', true);*/
                    if(clickedIndex==0){
                        let currentDate = new Date();

                        let beginDate = util.toDateString(currentDate, format)+' 00:00:00';
                        let endDate = util.toDateString(currentDate, format)+' 23:59:59';
                        $('#date').val(beginDate+' ~ '+endDate )

                    }
                    if(clickedIndex==1){
                        let currentDate = new Date();
                        let date = new Date();
                        currentDate.setDate((currentDate.getDate())-7);
                        let endDate = util.toDateString(date,format)+' 00:00:00';
                        let beginDate = util.toDateString(currentDate, format)+' 23:59:59';
                        $('#date').val(beginDate+' ~ '+endDate )

                    }
                }
            });

        });
        $('#dateType2').on('changed.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            layui.use('util', function(){
                var util = layui.util;
                let format = 'yyyy-MM-dd'
                //示例
                if(clickedIndex==2){
                    $('#date2').prop('disabled', false);

                }else {
                    /*$('#date').prop('disabled', true);*/
                    if(clickedIndex==0){
                        let currentDate = new Date();

                        let beginDate = util.toDateString(currentDate, format);
                        let endDate = util.toDateString(currentDate, format);
                        $('#date2').val(beginDate+' ~ '+endDate )

                    }
                    if(clickedIndex==1){
                        let currentDate = new Date();
                        let date = new Date();
                        currentDate.setDate((currentDate.getDate())-7);
                        let endDate = util.toDateString(date,format);
                        let beginDate = util.toDateString(currentDate, format);
                        $('#date2').val(beginDate+' ~ '+endDate )

                    }
                }
            });

        });
        $('#countType2').on('changed.bs.select', function (e, clickedIndex, isSelected, previousValue) {
            if(clickedIndex==1){
                cols2 = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '操作日期',
                        field: 'createDate',
                        align: 'center',
                        totalRowText: '小计',
                        templet: function (d) {
                            return '<span>' + d.createDate.substring(0,10) + '</span>'
                        }
                    }
                    , {
                        title: "总上分积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总下分积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总赠送积分",
                        field: "sumGiveMoney",
                        align: 'center',
                        totalRowText: '总赠送积分',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if (clickedIndex==2){
                cols2 = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '用户账号',
                        field: 'username',
                        align: 'center',
                        totalRowText: '小计',
                        /*templet: function (d) {
                            return '<span>' + d.createDate.substring(0,10) + '</span>'
                        }*/
                    }, {
                        title: '用户昵称',
                        field: 'userNickName',
                        align: 'center',
                        /*templet: function (d) {
                            return '<span>' + d.createDate.substring(0,10) + '</span>'
                        }*/
                    }
                    , {
                        title: "总上分积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总下分积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总赠送积分",
                        field: "sumGiveMoney",
                        align: 'center',
                        totalRowText: '总赠送积分',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }
            if(clickedIndex==3){
                cols2 = [[ //标题栏
                    /*{type: 'radio', fixed: 'left'},*/
                    {
                        field: 'id',
                        title: 'ID',
                        width: 80,
                        hide: true
                        /*sort: true*/
                    }, {
                        title: '操作日期',
                        field: 'createDate',
                        align: 'center',
                        totalRowText: '小计',
                        templet: function (d) {
                            return '<span>' + d.createDate.substring(0,10) + '</span>'
                        }
                    }, {
                        title: '用户账号',
                        field: 'username',
                        align: 'center',
                        totalRowText: '小计',
                        /*templet: function (d) {
                            return '<span>' + d.createDate.substring(0,10) + '</span>'
                        }*/
                    }, {
                        title: '用户昵称',
                        field: 'userNickName',
                        align: 'center',
                        /*templet: function (d) {
                            return '<span>' + d.createDate.substring(0,10) + '</span>'
                        }*/
                    }
                    , {
                        title: "总上分积分",
                        field: "xiaMoney",
                        align: 'center',
                        totalRowText: '总收入',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                    , {
                        title: "总下分积分",
                        field: "lotteryMoney",
                        align: 'center',
                        totalRowText: '总支出',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总赠送积分",
                        field: "sumGiveMoney",
                        align: 'center',
                        totalRowText: '总赠送积分',
                        totalRow: true
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }, {
                        title: "总盈亏",
                        field: "profitLoss",
                        align: 'center',
                        totalRowText: '总盈亏',
                        totalRow: true,
                        templet: function (d) {
                            if (d.profitLoss < 0) {
                                return '<span style="color: red">' + d.profitLoss + '</span>'
                            } else {
                                return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                            }

                            return d.profitLoss

                        }
                        /*sort: true*/
                        /* , templet: function (d) {
                             return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                         }*/
                    }
                ]]
            }

        });
        //目录
        var siteDir = $('.site-dir');
        if (siteDir[0] && $(window).width() > 750) {
           /* layer.ready(function () {
                layer.open({
                    type: 1
                    , content: siteDir
                    , skin: 'layui-layer-dir'
                    , area: 'auto'
                    , maxHeight: $(window).height() - 300
                    , title: '统计表导航'
                    , closeBtn: false
                    , offset: 'r'
                    , shade: false
                    , success: function (layero, index) {
                        layer.style(index, {
                            marginLeft: -15,zIndex:9999
                        });
                    }
                });
            });*/
            siteDir.find('li').on('click', function () {
                var othis = $(this);
                othis.find('a').addClass('layui-this');
                othis.siblings().find('a').removeClass('layui-this');
            });
        }
    });

    function reset() {
        $('#date').val('');
        $('#isAdmin').selectpicker('val', '');
        $('#user').selectpicker('val', '');
        $('#banhao').selectpicker('val', '');
        $('#juhao').selectpicker('val', '');

        $('#dateType').selectpicker('val', '3');
        $('#countType').selectpicker('val', '1');
        $('#countJu').selectpicker('val', '3');
        $('#countJu').prop('disabled', false);
        $('#countJu').selectpicker('refresh');
        cols = [[ //标题栏
            /*{type: 'radio', fixed: 'left'},*/
            {
                field: 'id',
                title: 'ID',
                width: 80,
                hide: true
                /*sort: true*/
            }, {
                title: '版号',
                field: 'banhao',
                align: 'center',
                totalRowText: '小计'
            }, {
                title: "局号",
                field: "qihao",
                align: 'center'
                /*sort: true*/
                /* , templet: function (d) {
                     return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                 }*/
            }
            , {
                title: "总下注积分",
                field: "xiaMoney",
                align: 'center',
                totalRowText: '总收入',
                totalRow: true
                /*sort: true*/
                /* , templet: function (d) {
                     return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                 }*/
            }
            , {
                title: "总中奖积分",
                field: "lotteryMoney",
                align: 'center',
                totalRowText: '总支出',
                totalRow: true
                /*sort: true*/
                /* , templet: function (d) {
                     return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                 }*/
            }, {
                title: "总盈亏",
                field: "profitLoss",
                align: 'center',
                totalRowText: '总盈亏',
                totalRow: true,
                templet: function (d) {
                    if (d.profitLoss < 0) {
                        return '<span style="color: red">' + d.profitLoss + '</span>'
                    } else {
                        return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                    }

                    return d.profitLoss

                }
                /*sort: true*/
                /* , templet: function (d) {
                     return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                 }*/
            }
        ]]

    }
    function reset2() {
        $('#date2').val('');
        $('#isAdmin2').selectpicker('val', '');
        $('#user2').selectpicker('val', '');

        $('#dateType2').selectpicker('val', '3');
        $('#countType2').selectpicker('val', '1');

        cols2 = [[ //标题栏
            /*{type: 'radio', fixed: 'left'},*/
            {
                field: 'id',
                title: 'ID',
                width: 80,
                hide: true
                /*sort: true*/
            }, {
                title: '操作日期',
                field: 'createDate',
                align: 'center',
                totalRowText: '小计',
                templet: function (d) {
                    return '<span>' + d.createDate.substring(0,10) + '</span>'
                }
            }
            , {
                title: "总上分积分",
                field: "xiaMoney",
                align: 'center',
                totalRowText: '总收入',
                totalRow: true
                /*sort: true*/
                /* , templet: function (d) {
                     return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                 }*/
            }
            , {
                title: "总下分积分",
                field: "lotteryMoney",
                align: 'center',
                totalRowText: '总支出',
                totalRow: true
                /*sort: true*/
                /* , templet: function (d) {
                     return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                 }*/
            }, {
                title: "总赠送积分",
                field: "sumGiveMoney",
                align: 'center',
                totalRowText: '总赠送积分',
                totalRow: true
                /*sort: true*/
                /* , templet: function (d) {
                     return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                 }*/
            }, {
                title: "总盈亏",
                field: "profitLoss",
                align: 'center',
                totalRowText: '总盈亏',
                totalRow: true,
                templet: function (d) {
                    if (d.profitLoss < 0) {
                        return '<span style="color: red">' + d.profitLoss + '</span>'
                    } else {
                        return '<span style="color:#4f93fe ">' + d.profitLoss + '</span>'
                    }

                    return d.profitLoss

                }
                /*sort: true*/
                /* , templet: function (d) {
                     return '<span>' + crtTimeFtt(d.createTime) + '</span>'
                 }*/
            }

        ]]

    }
    layui.use('util', function(){
        var util = layui.util;
        //执行
        util.fixbar({
            bar1: false
            ,click: function(type){
                console.log(type);
                if(type === 'bar1'){
                    alert('点击了bar1')
                }
            }
        });
    });
    function tableReload() {
        layui.use('table', function () {
            var table = layui.table;
            table.reload('table');
        })
    }
    function exportFile() {
        var date = $('#date').val();
        var user = $('#user').val();
        var banhao = $('#banhao').val()?$('#banhao').val():'';
        var juhao = $('#juhao').val()? $('#juhao').val():''
        let username = '';
        let isAdmin = $('#isAdmin').val()
        if (user) {
            username = user.join(',');
        }
        if (banhao) {
            banhao = banhao.join(',')
        }
        if (juhao) {
            juhao = juhao.join(',')
        }
        let countType = $("#countType").val()
        let countJu = $("#countJu").val();
        let dateType = $('#dateType').val();
        let url = "${home}"+'/userLottery/exportExcel?dateStr='+date+'&username='+username+'&banhao='+banhao+
            '&juhao='+juhao+'&isAdmin='+isAdmin+'&countType='+countType+'&countJu='+countJu;
        window.location.href = url;
    }
    function exportFile2() {
        var date = $('#date2').val();
        var user = $('#user2').val();
        let username = '';
        if (user) {
            username = user.join(',');
        }

        let countType = $("#countType2").val()
        let url = "${home}"+'/recharge/exportExcel?dateStr='+date+'&username='+username+
           '&countType='+countType;
        window.location.href = url;
    }

    $.fn.modal.Constructor.prototype.enforceFocus = function () {
    };
</script>
<script type="text/html" id="toolbarDemo">
    <span>用户投注统计表</span>
</script>
<script type="text/html" id="toolbarDemo2">
    <span>用户上下分统计表</span>
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
        width: 145px !important;
    }

    .isAdmin {
        width: 100px;
    }

    .actions-btn {
        width: 46% !important;
        margin-left: 5px !important;
    }
</style>
</html>
