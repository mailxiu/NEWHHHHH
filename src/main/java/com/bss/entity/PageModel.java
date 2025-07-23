/*    */
package com.bss.entity;

import java.util.Objects;

/*    */ public class PageModel {
    /*    */   private Integer pageIndex;
    /*    */   private Integer size;
    /*    */   private String action;
    /*    */   private String time;
    /*    */   private String startTime;
    /*    */   private String endTime;

    /*    */
    public PageModel(Integer pageIndex, Integer size, String action, String time) {
        /* 21 */
        this.pageIndex = Integer.valueOf((pageIndex == null) ? 1 : pageIndex.intValue());
        /* 22 */
        this.size = Integer.valueOf((size == null) ? 10 : size.intValue());
        /* 23 */
        this.action = (action == null) ? "refresh" : action;
        /* 24 */
        this.time = (time == null) ? "" : time;
        /*    */
        /* 26 */
        if (!this.time.equals("")) {
            /* 27 */
            String[] split = time.split(" - ");
            /* 28 */
            this.startTime = split[0].trim() + " 00:00:00";
            /* 29 */
            this.endTime = split[1].trim() + " 23:59:59";
            /*    */
        }
        /*    */
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.PageModel)) return false;
        com.bss.entity.PageModel other = (com.bss.entity.PageModel) o;
        if (!other.canEqual(this)) return false;
        Object this$pageIndex = getPageIndex(), other$pageIndex = other.getPageIndex();
        if (!Objects.equals(this$pageIndex, other$pageIndex))
            return false;
        Object this$size = getSize(), other$size = other.getSize();
        if (!Objects.equals(this$size, other$size)) return false;
        Object this$action = getAction(), other$action = other.getAction();
        if (!Objects.equals(this$action, other$action)) return false;
        Object this$time = getTime(), other$time = other.getTime();
        if (!Objects.equals(this$time, other$time)) return false;
        Object this$startTime = getStartTime(), other$startTime = other.getStartTime();
        if (!Objects.equals(this$startTime, other$startTime))
            return false;
        Object this$endTime = getEndTime(), other$endTime = other.getEndTime();
        return !(!Objects.equals(this$endTime, other$endTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.PageModel;
    }


    public String toString() {
        return "PageModel(pageIndex=" + getPageIndex() + ", size=" + getSize() + ", action=" + getAction() + ", time=" + getTime() + ", startTime=" + getStartTime() + ", endTime=" + getEndTime() + ")";
    }

    /*    */
    /*    */
    /* 13 */
    public Integer getPageIndex() {
        return this.pageIndex;
    }

    /*    */
    /* 10 */
    public void setPageIndex(Integer pageIndex) {
        this.pageIndex = pageIndex;
    }

    /* 14 */
    public Integer getSize() {
        return this.size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    /* 15 */
    public String getAction() {
        return this.action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    /* 16 */
    public String getTime() {
        return this.time;
    }

    /*    */
    /*    */
    public void setTime(String time) {
        /* 34 */
        this.time = time;
        /* 35 */
        if (!this.time.equals("")) {
            /* 36 */
            String[] split = time.split(" - ");
            /* 37 */
            this.startTime = split[0].trim() + " 00:00:00";
            /* 38 */
            this.endTime = split[1].trim() + " 23:59:59";
            /*    */
        }
        /*    */
    }

    /* 17 */
    public String getStartTime() {
        return this.startTime;
    }

    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }

    public String getEndTime() {
        /* 18 */
        return this.endTime;
        /*    */
    }

    public void setEndTime(String endTime) {
        this.endTime = endTime;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\PageModel.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */