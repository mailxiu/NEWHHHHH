package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

@TableName("configure")
public class Configure {
    private Integer id;
    private String merchant;
    private Integer indexAd;
    private Integer extract;
    private Integer marketing;
    private Integer notice;
    private String noticeUrl;
    private Integer payMode;
    private Double payPoints;
    private Double payPercent;
    private Integer payStart;
    private Double automaticPayment;
    private Integer withdrawalNumber;
    private String payChannelName;
    private String payChannelImage;
    private Integer onlinePayment;
    private Integer onlineAlipay;
    private Integer onlineCustomer;
    private String paymentProvider;
    private Integer paymentPolling;
    private String paymentRouting;
    private Integer wechatLogin;
    private Integer appleLogin;
    private Integer examine;
    private Integer version;
    // 新增字段：审核品牌
    private String brands;

    // setter methods
    public void setId(Integer id) {
        this.id = id;
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public void setIndexAd(Integer indexAd) {
        this.indexAd = indexAd;
    }

    public void setExtract(Integer extract) {
        this.extract = extract;
    }

    public void setMarketing(Integer marketing) {
        this.marketing = marketing;
    }

    public void setNotice(Integer notice) {
        this.notice = notice;
    }

    public void setNoticeUrl(String noticeUrl) {
        this.noticeUrl = noticeUrl;
    }

    public void setPayMode(Integer payMode) {
        this.payMode = payMode;
    }

    public void setPayPoints(Double payPoints) {
        this.payPoints = payPoints;
    }

    public void setPayPercent(Double payPercent) {
        this.payPercent = payPercent;
    }

    public void setPayStart(Integer payStart) {
        this.payStart = payStart;
    }

    public void setAutomaticPayment(Double automaticPayment) {
        this.automaticPayment = automaticPayment;
    }

    public void setWithdrawalNumber(Integer withdrawalNumber) {
        this.withdrawalNumber = withdrawalNumber;
    }

    public void setPayChannelName(String payChannelName) {
        this.payChannelName = payChannelName;
    }

    public void setPayChannelImage(String payChannelImage) {
        this.payChannelImage = payChannelImage;
    }

    public void setOnlinePayment(Integer onlinePayment) {
        this.onlinePayment = onlinePayment;
    }

    public void setOnlineAlipay(Integer onlineAlipay) {
        this.onlineAlipay = onlineAlipay;
    }

    public void setOnlineCustomer(Integer onlineCustomer) {
        this.onlineCustomer = onlineCustomer;
    }

    public void setPaymentProvider(String paymentProvider) {
        this.paymentProvider = paymentProvider;
    }

    public void setPaymentPolling(Integer paymentPolling) {
        this.paymentPolling = paymentPolling;
    }

    public void setPaymentRouting(String paymentRouting) {
        this.paymentRouting = paymentRouting;
    }

    public void setWechatLogin(Integer wechatLogin) {
        this.wechatLogin = wechatLogin;
    }

    public void setAppleLogin(Integer appleLogin) {
        this.appleLogin = appleLogin;
    }

    public void setExamine(Integer examine) {
        this.examine = examine;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    // 新增setter
    public void setBrands(String brands) {
        this.brands = brands;
    }

    // getter methods
    public Integer getId() {
        return this.id;
    }

    public String getMerchant() {
        return this.merchant;
    }

    public Integer getIndexAd() {
        return this.indexAd;
    }

    public Integer getExtract() {
        return this.extract;
    }

    public Integer getMarketing() {
        return this.marketing;
    }

    public Integer getNotice() {
        return this.notice;
    }

    public String getNoticeUrl() {
        return this.noticeUrl;
    }

    public Integer getPayMode() {
        return this.payMode;
    }

    public Double getPayPoints() {
        return this.payPoints;
    }

    public Double getPayPercent() {
        return this.payPercent;
    }

    public Integer getPayStart() {
        return this.payStart;
    }

    public Double getAutomaticPayment() {
        return this.automaticPayment;
    }

    public Integer getWithdrawalNumber() {
        return this.withdrawalNumber;
    }

    public String getPayChannelName() {
        return this.payChannelName;
    }

    public String getPayChannelImage() {
        return this.payChannelImage;
    }

    public Integer getOnlinePayment() {
        return this.onlinePayment;
    }

    public Integer getOnlineAlipay() {
        return this.onlineAlipay;
    }

    public Integer getOnlineCustomer() {
        return this.onlineCustomer;
    }

    public String getPaymentProvider() {
        return this.paymentProvider;
    }

    public Integer getPaymentPolling() {
        return this.paymentPolling;
    }

    public String getPaymentRouting() {
        return this.paymentRouting;
    }

    public Integer getWechatLogin() {
        return this.wechatLogin;
    }

    public Integer getAppleLogin() {
        return this.appleLogin;
    }

    public Integer getExamine() {
        return this.examine;
    }

    public Integer getVersion() {
        return this.version;
    }

    // 新增getter
    public String getBrands() {
        return this.brands;
    }

    // equals、hashCode、toString 方法（可选，根据实际项目需要加上）

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Configure)) return false;
        Configure other = (Configure) o;
        if (!other.canEqual(this)) return false;
        if (id != null ? !id.equals(other.id) : other.id != null) return false;
        if (merchant != null ? !merchant.equals(other.merchant) : other.merchant != null) return false;
        if (indexAd != null ? !indexAd.equals(other.indexAd) : other.indexAd != null) return false;
        if (extract != null ? !extract.equals(other.extract) : other.extract != null) return false;
        if (marketing != null ? !marketing.equals(other.marketing) : other.marketing != null) return false;
        if (notice != null ? !notice.equals(other.notice) : other.notice != null) return false;
        if (noticeUrl != null ? !noticeUrl.equals(other.noticeUrl) : other.noticeUrl != null) return false;
        if (payMode != null ? !payMode.equals(other.payMode) : other.payMode != null) return false;
        if (payPoints != null ? !payPoints.equals(other.payPoints) : other.payPoints != null) return false;
        if (payPercent != null ? !payPercent.equals(other.payPercent) : other.payPercent != null) return false;
        if (payStart != null ? !payStart.equals(other.payStart) : other.payStart != null) return false;
        if (automaticPayment != null ? !automaticPayment.equals(other.automaticPayment) : other.automaticPayment != null) return false;
        if (withdrawalNumber != null ? !withdrawalNumber.equals(other.withdrawalNumber) : other.withdrawalNumber != null) return false;
        if (payChannelName != null ? !payChannelName.equals(other.payChannelName) : other.payChannelName != null) return false;
        if (payChannelImage != null ? !payChannelImage.equals(other.payChannelImage) : other.payChannelImage != null) return false;
        if (onlinePayment != null ? !onlinePayment.equals(other.onlinePayment) : other.onlinePayment != null) return false;
        if (onlineAlipay != null ? !onlineAlipay.equals(other.onlineAlipay) : other.onlineAlipay != null) return false;
        if (onlineCustomer != null ? !onlineCustomer.equals(other.onlineCustomer) : other.onlineCustomer != null) return false;
        if (paymentProvider != null ? !paymentProvider.equals(other.paymentProvider) : other.paymentProvider != null) return false;
        if (paymentPolling != null ? !paymentPolling.equals(other.paymentPolling) : other.paymentPolling != null) return false;
        if (paymentRouting != null ? !paymentRouting.equals(other.paymentRouting) : other.paymentRouting != null) return false;
        if (wechatLogin != null ? !wechatLogin.equals(other.wechatLogin) : other.wechatLogin != null) return false;
        if (appleLogin != null ? !appleLogin.equals(other.appleLogin) : other.appleLogin != null) return false;
        if (examine != null ? !examine.equals(other.examine) : other.examine != null) return false;
        if (version != null ? !version.equals(other.version) : other.version != null) return false;
        if (brands != null ? !brands.equals(other.brands) : other.brands != null) return false;
        return true;
    }

    protected boolean canEqual(Object other) {
        return other instanceof Configure;
    }

    @Override
    public String toString() {
        return "Configure(id=" + getId() +
                ", merchant=" + getMerchant() +
                ", indexAd=" + getIndexAd() +
                ", extract=" + getExtract() +
                ", marketing=" + getMarketing() +
                ", notice=" + getNotice() +
                ", noticeUrl=" + getNoticeUrl() +
                ", payMode=" + getPayMode() +
                ", payPoints=" + getPayPoints() +
                ", payPercent=" + getPayPercent() +
                ", payStart=" + getPayStart() +
                ", automaticPayment=" + getAutomaticPayment() +
                ", withdrawalNumber=" + getWithdrawalNumber() +
                ", payChannelName=" + getPayChannelName() +
                ", payChannelImage=" + getPayChannelImage() +
                ", onlinePayment=" + getOnlinePayment() +
                ", onlineAlipay=" + getOnlineAlipay() +
                ", onlineCustomer=" + getOnlineCustomer() +
                ", paymentProvider=" + getPaymentProvider() +
                ", paymentPolling=" + getPaymentPolling() +
                ", paymentRouting=" + getPaymentRouting() +
                ", wechatLogin=" + getWechatLogin() +
                ", appleLogin=" + getAppleLogin() +
                ", examine=" + getExamine() +
                ", version=" + getVersion() +
                ", brands=" + getBrands() +
                ")";
    }
}