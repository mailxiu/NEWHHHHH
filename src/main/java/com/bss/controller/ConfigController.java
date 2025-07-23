package com.bss.controller;

import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.bss.entity.AppletConfig;
import com.bss.entity.ArticleConfig;
import com.bss.entity.Configure;
import com.bss.entity.MessageConfig;
import com.bss.entity.OfficialConfig;
import com.bss.entity.PayAlipayConfig;
import com.bss.entity.PaymentConfig;
import com.bss.entity.PresetConfig;
import com.bss.entity.SystemConfig;
import com.bss.entity.User;
import com.bss.entity.WechatAppPayConfig;
import com.bss.service.impl.AppletConfigServiceImpl;
import com.bss.service.impl.ArticleConfigServiceImpl;
import com.bss.service.impl.ConfigureServiceImpl;
import com.bss.service.impl.MessageConfigServiceImpl;
import com.bss.service.impl.OfficialConfigServiceImpl;
import com.bss.service.impl.PayAlipayConfigServiceImpl;
import com.bss.service.impl.PaymentConfigServiceImpl;
import com.bss.service.impl.PresetConfigServiceImpl;
import com.bss.service.impl.SystemConfigServiceImpl;
import com.bss.service.impl.WechatAppPayConfigServiceImpl;
import com.bss.utils.R;
import org.springframework.beans.BeanUtils;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.util.*;
import java.util.stream.Collectors;

@RequestMapping({"/config"})
@RestController
public class ConfigController {

    @Resource
    private PayAlipayConfigServiceImpl payAlipayConfigService;
    @Resource
    private PaymentConfigServiceImpl paymentConfigService;
    @Resource
    private AppletConfigServiceImpl appletConfigService;
    @Resource
    private OfficialConfigServiceImpl officialConfigService;
    @Resource
    private ConfigureServiceImpl configureService;
    @Resource
    private SystemConfigServiceImpl systemConfigService;
    @Resource
    private ArticleConfigServiceImpl articleConfigService;
    @Resource
    private MessageConfigServiceImpl messageConfigService;
    @Resource
    private PresetConfigServiceImpl presetConfigService;
    @Resource
    private WechatAppPayConfigServiceImpl wechatAppPayConfigService;

    @RequestMapping({"/payment"})
    public R payment(String merchantId, String merchantSerialNumber, String apiV3Key, String privateKeyFromPath, String publicKeyFromPath, String publicKeyId) {
        PaymentConfig payment = (PaymentConfig) this.paymentConfigService.getOne(new QueryWrapper<>());
        if (payment == null) {
            payment = new PaymentConfig();
            payment.setId(0);
        }
        payment.setMerchantId(merchantId);
        payment.setMerchantSerialNumber(merchantSerialNumber);
        payment.setApiV3Key(apiV3Key);
        payment.setPrivateKeyFromPath(privateKeyFromPath);
        payment.setPublicKeyFromPath(publicKeyFromPath);
        payment.setPublicKeyId(publicKeyId);

        boolean saveOrUpdate = this.paymentConfigService.saveOrUpdate(payment);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    @RequestMapping({"/weChatAppPay"})
    public R weChatAppPay(String merchantId, String merchantSerialNumber, String apiV3Key, String privateKeyFromPath, String publicKeyFromPath, String publicKeyId) {
        WechatAppPayConfig payment = (WechatAppPayConfig) this.wechatAppPayConfigService.getOne(new QueryWrapper<>());
        if (payment == null) {
            payment = new WechatAppPayConfig();
            payment.setId(0);
        }
        payment.setMerchantId(merchantId);
        payment.setMerchantSerialNumber(merchantSerialNumber);
        payment.setApiV3Key(apiV3Key);
        payment.setPrivateKeyFromPath(privateKeyFromPath);
        payment.setPublicKeyFromPath(publicKeyFromPath);
        payment.setPublicKeyId(publicKeyId);

        boolean saveOrUpdate = this.wechatAppPayConfigService.saveOrUpdate(payment);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    @RequestMapping({"/alipay"})
    public R alipay(String appid, String privateKey, String alipayPublicKey) {
        PayAlipayConfig payAlipayConfig = (PayAlipayConfig) this.payAlipayConfigService.getOne(new QueryWrapper<>());
        if (payAlipayConfig == null) {
            payAlipayConfig = new PayAlipayConfig();
            payAlipayConfig.setId(0);
        }
        payAlipayConfig.setAppid(appid);
        payAlipayConfig.setPrivateKey(privateKey);
        payAlipayConfig.setAlipayPublicKey(alipayPublicKey);

        boolean saveOrUpdate = this.payAlipayConfigService.saveOrUpdate(payAlipayConfig);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    @RequestMapping({"/applet"})
    public R applet(String appid, String secret) {
        AppletConfig applet = (AppletConfig) this.appletConfigService.getOne(new QueryWrapper<>());
        if (applet == null) {
            applet = new AppletConfig();
            applet.setId(0);
        }
        applet.setAppId(appid);
        applet.setSecret(secret);

        boolean saveOrUpdate = this.appletConfigService.saveOrUpdate(applet);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    @RequestMapping({"/official"})
    public R official(String appid, String appSecret, String officialName, String officialImage) {
        OfficialConfig officialConfig = (OfficialConfig) this.officialConfigService.getOne(new QueryWrapper<>());
        if (officialConfig == null) {
            officialConfig = new OfficialConfig();
            officialConfig.setId(0);
        }
        officialConfig.setAppId(appid);
        officialConfig.setAppSecret(appSecret);
        officialConfig.setOfficialName(officialName);
        officialConfig.setOfficialImage(officialImage);

        boolean saveOrUpdate = this.officialConfigService.saveOrUpdate(officialConfig);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    // 后台保存配置（此处建议增加 brands 字段参数，如果前端有传brands就加上，否则原逻辑即可）
    @RequestMapping({"/configure"})
    public R configure(Integer extract, Integer indexAd, Integer marketing, Integer onlinePayment, Integer onlineAlipay, Integer onlineCustomer, String paymentProvider, Integer paymentPolling, String paymentRouting, Integer wechatLogin, Integer appleLogin, Integer examine, Integer version, String brands, HttpSession session) {
        User user = (User) session.getAttribute("user");
        Configure configure = (Configure) this.configureService.getOne(new QueryWrapper<>());
        if (configure == null) {
            configure = new Configure();
            configure.setId(0);
            configure.setMerchant(user.getMerchant());
        }
        configure.setIndexAd(indexAd);
        configure.setExtract(extract);
        configure.setMarketing(marketing);
        configure.setOnlinePayment(onlinePayment);
        configure.setOnlineAlipay(onlineAlipay);
        configure.setOnlineCustomer(onlineCustomer);
        configure.setPaymentProvider(paymentProvider);
        configure.setPaymentPolling(paymentPolling);
        configure.setPaymentRouting(paymentRouting);
        configure.setWechatLogin(wechatLogin);
        configure.setAppleLogin(appleLogin);
        configure.setExamine(examine);
        configure.setVersion(version);
        configure.setBrands(brands); // 新增品牌保存

        boolean saveOrUpdate = this.configureService.saveOrUpdate(configure);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    @RequestMapping({"/system"})
    public R applet(String serviceUrl, String galleryUrl, String galleryRoute, String websiteTitle, String menuTitle, HttpSession session) {
        User user = (User) session.getAttribute("user");
        SystemConfig systemConfig = (SystemConfig) this.systemConfigService.getOne(new QueryWrapper<>());
        if (systemConfig == null) {
            systemConfig = new SystemConfig();
            systemConfig.setId(0);
        }
        systemConfig.setServiceUrl(serviceUrl);
        systemConfig.setGalleryUrl(galleryUrl);
        systemConfig.setGalleryRoute(galleryRoute);
        systemConfig.setWebsiteTitle(websiteTitle);
        systemConfig.setMenuTitle(menuTitle);

        boolean saveOrUpdate = this.systemConfigService.saveOrUpdate(systemConfig);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    @RequestMapping({"/article"})
    public R article(@ModelAttribute ArticleConfig requestData) {
        ArticleConfig articleConfig = (ArticleConfig) this.articleConfigService.getOne(new QueryWrapper<>());
        if (articleConfig == null) {
            articleConfig = new ArticleConfig();
            articleConfig.setId(0);
        }
        BeanUtils.copyProperties(requestData, articleConfig, new String[]{"id"});

        boolean saveOrUpdate = this.articleConfigService.saveOrUpdate(articleConfig);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    @RequestMapping({"/message"})
    public R message(String accessKeyId, String accessKeySecret, String regionId, String signName, String templateCode) {
        MessageConfig messageConfig = (MessageConfig) this.messageConfigService.getOne(new QueryWrapper<>());
        if (messageConfig == null) {
            messageConfig = new MessageConfig();
            messageConfig.setId(0);
        }
        messageConfig.setAccessKeyId(accessKeyId);
        messageConfig.setAccessKeySecret(accessKeySecret);
        messageConfig.setRegionId(regionId);
        messageConfig.setSignName(signName);
        messageConfig.setTemplateCode(templateCode);

        boolean saveOrUpdate = this.messageConfigService.saveOrUpdate(messageConfig);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    @RequestMapping({"/preset"})
    public R preset(String defaultPortrait, String projectPortrait, HttpSession session) {
        PresetConfig presetConfig = (PresetConfig) this.presetConfigService.getOne(new QueryWrapper<>());
        if (presetConfig == null) {
            presetConfig = new PresetConfig();
            presetConfig.setId(0);
        }
        presetConfig.setDefaultPortrait(defaultPortrait);
        presetConfig.setProjectPortrait(projectPortrait);

        boolean saveOrUpdate = this.presetConfigService.saveOrUpdate(presetConfig);

        return R.success(Boolean.valueOf(saveOrUpdate));
    }

    // ----------- 关键：返回APP端配置并加品牌判断逻辑 -----------
    /**
     * 返回APP端配置，带上审核品牌判断逻辑
     * 建议APP端请求此接口时传递brand和version参数
     * 如 /config/sel?merchant=xxx&brand=huawei&version=1
     */
    @RequestMapping({"/sel"})
    public R getMerchantConfig(String merchant, String brand, String version) {
        Configure configure = (Configure) this.configureService.getOne(new QueryWrapper<Configure>().eq("merchant", merchant));
        Map<String, Object> configureData = new HashMap<>();
        if (configure != null) {
            // 拷贝所有属性
            configureData.put("id", configure.getId());
            configureData.put("merchant", configure.getMerchant());
            configureData.put("indexAd", configure.getIndexAd());
            configureData.put("extract", configure.getExtract());
            configureData.put("marketing", configure.getMarketing());
            configureData.put("notice", configure.getNotice());
            configureData.put("noticeUrl", configure.getNoticeUrl());
            configureData.put("payMode", configure.getPayMode());
            configureData.put("payPoints", configure.getPayPoints());
            configureData.put("payPercent", configure.getPayPercent());
            configureData.put("payStart", configure.getPayStart());
            configureData.put("automaticPayment", configure.getAutomaticPayment());
            configureData.put("withdrawalNumber", configure.getWithdrawalNumber());
            configureData.put("payChannelName", configure.getPayChannelName());
            configureData.put("payChannelImage", configure.getPayChannelImage());
            configureData.put("onlinePayment", configure.getOnlinePayment());
            configureData.put("onlineAlipay", configure.getOnlineAlipay());
            configureData.put("onlineCustomer", configure.getOnlineCustomer());
            configureData.put("paymentProvider", configure.getPaymentProvider());
            configureData.put("paymentPolling", configure.getPaymentPolling());
            configureData.put("paymentRouting", configure.getPaymentRouting());
            configureData.put("wechatLogin", configure.getWechatLogin());
            configureData.put("appleLogin", configure.getAppleLogin());
            configureData.put("version", configure.getVersion());
            configureData.put("brands", configure.getBrands());
            // 关键：只要brands非空且命中，开关=1且版本号一致，才examine=1，否则全部0
            boolean examineFlag = false;
            if (configure.getExamine() != null && configure.getExamine() == 1) {
                if (configure.getVersion() != null && configure.getVersion().toString().equals(version)) {
                    String brands = configure.getBrands();
                    if (brands != null && !brands.trim().isEmpty()) {
                        List<String> brandList = Arrays.stream(brands.split(","))
                                .map(String::trim)
                                .map(String::toLowerCase)
                                .collect(Collectors.toList());
                        if (brand != null && brandList.contains(brand.trim().toLowerCase())) {
                            examineFlag = true;
                        }
                    }
                }
            }
            configureData.put("examine", examineFlag ? 1 : 0);
        }

        OfficialConfig officialConfig = (OfficialConfig) this.officialConfigService.getOne(new QueryWrapper<>());
        if (officialConfig != null) {
            configureData.put("officialName", officialConfig.getOfficialName());
            configureData.put("officialImage", officialConfig.getOfficialImage());
        }
        Map<String, Object> data = new HashMap<>();
        data.put("config", configureData);
        return R.success(data);
    }
}