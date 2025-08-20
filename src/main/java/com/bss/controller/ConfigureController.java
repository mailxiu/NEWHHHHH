package com.bss.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.api.ApiController;
import com.baomidou.mybatisplus.extension.api.R;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.bss.entity.Configure;
import com.bss.entity.OfficialConfig;
import com.bss.entity.PayVo;
import com.bss.entity.User;
import org.apache.shiro.authz.annotation.RequiresRoles; // 记得引入Shiro注解
import com.bss.service.ConfigureService;
import com.bss.service.impl.OfficialConfigServiceImpl;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping({"config"})
public class ConfigureController extends ApiController {

    @Resource
    private ConfigureService configureService;
    @Resource
    private OfficialConfigServiceImpl officialConfigService;

    @GetMapping
    public R selectAll(Page<Configure> page, Configure configure) {
        return success(this.configureService.page((IPage) page, (Wrapper) new QueryWrapper(configure)));
    }

    @GetMapping({"/{id}"})
    public R selectOne(@PathVariable Serializable id) {
        return success(this.configureService.getById(id));
    }

    @GetMapping({"/get"})
    public R selectOneByMerchant(String merchant) {
        Configure configure = (Configure) this.configureService.getOne((Wrapper) (new QueryWrapper()).eq("merchant", merchant));
        return success(configure);
    }

    @GetMapping({"/sel"})
    public R getMerchantConfig(String merchant) {
        Configure configure = (Configure) this.configureService.getOne((Wrapper) (new QueryWrapper()).eq("merchant", merchant));
        JSONObject configureData = (JSONObject) JSON.toJSON(configure);

        OfficialConfig officialConfig = (OfficialConfig) this.officialConfigService.getOne((Wrapper) new QueryWrapper());
        configureData.put("officialName", officialConfig.getOfficialName());
        configureData.put("officialImage", officialConfig.getOfficialImage());

        JSONObject data = new JSONObject();
        data.put("config", configureData);
        return success(data);
    }

    @RequiresRoles("Admin")
    @PostMapping({"/updatePay"})
    public R updatePay(PayVo payVo, HttpSession session) {
        User user = (User) session.getAttribute("user");
        if (user == null) {
            return success(Boolean.FALSE);
        }
        Configure configure = (Configure) this.configureService.getOne((Wrapper) (new QueryWrapper()).eq("merchant", user.getMerchant()));
        configure.setPayMode(payVo.getPayMode());
        configure.setPayPoints(payVo.getPayPoints());
        configure.setPayPercent(payVo.getPayPercent());
        configure.setPayStart(payVo.getPayStart());
        configure.setAutomaticPayment(payVo.getAutomaticPayment());
        configure.setPayChannelName(payVo.getPayChannelName());
        configure.setPayChannelImage(payVo.getPayChannelImage());
        configure.setWithdrawalNumber(payVo.getWithdrawalNumber());
        boolean update = this.configureService.saveOrUpdate(configure);
        return success(Boolean.valueOf(update));
    }

    @RequiresRoles("Admin")
    @PutMapping
    public R update(@RequestBody Configure configure) {
        return success(Boolean.valueOf(this.configureService.updateById(configure)));
    }

    @RequiresRoles("Admin")
    @DeleteMapping
    public R delete(@RequestParam("idList") List<Long> idList) {
        return success(Boolean.valueOf(this.configureService.removeByIds(idList)));
    }

    /**
     * 给APP端用的获取审核配置接口，已合并品牌、版本、审核开关判断，并增加详细日志
     */
    @GetMapping({"/getConfigure"})
    public R getConfigure(HttpServletRequest request) {
        String merchant = request.getParameter("merchant");
        String version = request.getParameter("version");
        String brand = request.getParameter("brand");

        Configure configure = this.configureService.getOne(
                new QueryWrapper<Configure>().eq("merchant", merchant)
        );

        if (configure == null) {
            System.out.println("未找到商户配置: merchant=" + merchant);
            return success(Collections.singletonMap("config", new JSONObject()));
        }

        boolean examineFlag = false;
        String brands = configure.getBrands();
        System.out.println("brands字段: " + brands);
        System.out.println("brand参数: " + brand);

        // 审核判断逻辑
        if (configure.getExamine() != null && configure.getExamine() == 1) {
            if (configure.getVersion() != null && configure.getVersion().toString().equals(version)) {
                if (brands != null && !brands.trim().isEmpty()) {
                    List<String> brandList = Arrays.stream(brands.split(","))
                            .map(String::trim)
                            .map(String::toLowerCase)
                            .collect(Collectors.toList());
                    System.out.println("brandList: " + brandList);
                    if (brand != null && brandList.contains(brand.trim().toLowerCase())) {
                        examineFlag = true;
                    }
                }
                // brands为空时，所有品牌都不生效 examineFlag=false
            }
        }
        System.out.println("最终examineFlag: " + examineFlag);

        JSONObject configureData = (JSONObject) JSON.toJSON(configure);
        // 强制覆盖examine字段
        configureData.put("examine", examineFlag ? 1 : 0);

        // 官方信息也可保留
        OfficialConfig officialConfig = (OfficialConfig) this.officialConfigService.getOne((Wrapper) new QueryWrapper());
        if (officialConfig != null) {
            configureData.put("officialName", officialConfig.getOfficialName());
            configureData.put("officialImage", officialConfig.getOfficialImage());
        }

        JSONObject data = new JSONObject();
        data.put("config", configureData);
        return success(data);
    }
}