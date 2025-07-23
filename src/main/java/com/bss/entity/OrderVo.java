/*    */
package com.bss.entity;
/*    */
/*    */

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */ public class OrderVo
        /*    */ implements Serializable
        /*    */ {
    /*    */   private String unionid;
    /*    */   private String openid;
    /*    */   private Integer sort;
    /*    */   private String paymentType;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.OrderVo)) return false;
        com.bss.entity.OrderVo other = (com.bss.entity.OrderVo) o;
        if (!other.canEqual(this)) return false;
        Object this$unionid = getUnionid(), other$unionid = other.getUnionid();
        if (!Objects.equals(this$unionid, other$unionid)) return false;
        Object this$openid = getOpenid(), other$openid = other.getOpenid();
        if (!Objects.equals(this$openid, other$openid)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$paymentType = getPaymentType(), other$paymentType = other.getPaymentType();
        return !(!Objects.equals(this$paymentType, other$paymentType));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.OrderVo;
    }


    public String toString() {
        return "OrderVo(unionid=" + getUnionid() + ", openid=" + getOpenid() + ", sort=" + getSort() + ", paymentType=" + getPaymentType() + ")";
    }

    /*    */
    /*    */
    public String getUnionid() {
        /* 17 */
        return this.unionid;
        /*    */
    }

    /*    */
    /*    */
    public void setUnionid(String unionid) {
        /* 14 */
        this.unionid = unionid;
    }

    public String getOpenid() {
        /* 19 */
        return this.openid;
        /*    */
    }

    public void setOpenid(String openid) {
        this.openid = openid;
    }

    public Integer getSort() {
        /* 21 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public String getPaymentType() {
        /* 23 */
        return this.paymentType;
        /*    */
    }

    public void setPaymentType(String paymentType) {
        this.paymentType = paymentType;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\OrderVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */