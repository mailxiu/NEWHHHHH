/*    */
package com.bss.entity;
/*    */
/*    */

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */ public class DividendVO implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */   private Integer id;
    /*    */   private String relation;
    /*    */   private Integer requestGrade;
    private Integer responseGrade;
    private Double spread;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.DividendVO)) return false;
        com.bss.entity.DividendVO other = (com.bss.entity.DividendVO) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$relation = getRelation(), other$relation = other.getRelation();
        if (!Objects.equals(this$relation, other$relation)) return false;
        Object this$requestGrade = getRequestGrade(), other$requestGrade = other.getRequestGrade();
        if (!Objects.equals(this$requestGrade, other$requestGrade))
            return false;
        Object this$responseGrade = getResponseGrade(), other$responseGrade = other.getResponseGrade();
        if (!Objects.equals(this$responseGrade, other$responseGrade))
            return false;
        Object this$spread = getSpread(), other$spread = other.getSpread();
        return !(!Objects.equals(this$spread, other$spread));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.DividendVO;
    }


    public String toString() {
        return "DividendVO(id=" + getId() + ", relation=" + getRelation() + ", requestGrade=" + getRequestGrade() + ", responseGrade=" + getResponseGrade() + ", spread=" + getSpread() + ")";
    }

    /*    */
    public Integer getId() {
        /* 12 */
        return this.id;
        /*    */
    }

    /*    */
    /* 10 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getRelation() {
        /* 14 */
        return this.relation;
        /*    */
    }

    public void setRelation(String relation) {
        this.relation = relation;
    }

    public Integer getRequestGrade() {
        /* 16 */
        return this.requestGrade;
        /*    */
    }

    public void setRequestGrade(Integer requestGrade) {
        this.requestGrade = requestGrade;
    }

    public Integer getResponseGrade() {
        /* 18 */
        return this.responseGrade;
        /*    */
    }

    public void setResponseGrade(Integer responseGrade) {
        this.responseGrade = responseGrade;
    }

    public Double getSpread() {
        /* 20 */
        return this.spread;
        /*    */
    }

    public void setSpread(Double spread) {
        this.spread = spread;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\DividendVO.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */